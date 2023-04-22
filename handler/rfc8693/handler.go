// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/jwt"
	"github.com/ory/x/errorsx"
)

// #nosec G101
const (
	tokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"
	tokenTypeAT      = "urn:ietf:params:oauth:token-type:access_token"
)

type Handler struct {
	Storage              RFC8693Storage
	RefreshTokenStorage  oauth2.RefreshTokenStorage
	RefreshTokenStrategy oauth2.RefreshTokenStrategy

	Config interface {
		fosite.GrantTypeTokenExchangeCanSkipClientAuthProvider
		fosite.ScopeStrategyProvider
		fosite.AudienceStrategyProvider
		fosite.RefreshTokenScopesProvider
	}

	*oauth2.HandleHelper
}

type tokenExchangeParams struct {
	subjectToken     string
	subjectTokenType string
}

func parseRequestParameter(requester fosite.AccessRequester) (*tokenExchangeParams, error) {
	form := requester.GetRequestForm()

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	subject_token
	//		REQUIRED.  A security token that represents the identity of the
	//		party on behalf of whom the request is being made.  Typically, the
	//		subject of this token will be the subject of the security token
	//		issued in response to the request.
	subjectToken := form.Get("subject_token")
	if subjectToken == "" {
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("subject_token is missing"))
	}

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	subject_token_type
	//		REQUIRED.  An identifier, that indicates the type of the
	// 		security token in the "subject_token" parameter.
	subjectTokenType := form.Get("subject_token_type")
	switch subjectTokenType {
	case tokenTypeIDToken, tokenTypeAT:
	default:
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("unsupported or missing subject_token_type %s", subjectTokenType))
	}

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	requested_token_type
	//		OPTIONAL. An identifier, for the type of the requested security token.
	// 		If the requested type is unspecified,
	// 		the issued token type is at the discretion of the authorization server and
	// 		may be dictated by knowledge of the requirements of the service or
	// 		resource indicated by the resource or audience parameter.
	requestedTokenType := form.Get("requested_token_type")
	switch requestedTokenType {
	case tokenTypeAT, "":
	default:
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("unsupported requested_token_type %s", requestedTokenType))
	}

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	actor_token
	//		OPTIONAL . A security token that represents the identity of the acting party.
	//		Typically, this will be the party that is authorized to use the requested security
	//		token and act on behalf of the subject.
	actorToken := form.Get("actor_token")
	if actorToken != "" {
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("'actor_token' was provided but delegation is currently not supported."))
	}

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	actor_token_type
	//		An identifier, as described in Section 3, that indicates the type of the security token
	//		in the actor_token parameter. This is REQUIRED when the actor_token parameter is present
	//		in the request but MUST NOT be included otherwise.
	actorTokenType := form.Get("actor_token_type")
	if actorTokenType != "" {
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("'actor_token_type' was provided but delegation is currently not supported."))
	}

	return &tokenExchangeParams{
		subjectToken:     subjectToken,
		subjectTokenType: subjectTokenType,
	}, nil
}

func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	client := requester.GetClient()
	if client.GetID() == "" {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("unauthenticated client"))
	}

	// Check whether client is allowed to use token exchange.
	if !client.GetGrantTypes().Has(string(fosite.GrantTypeTokenExchange)) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("the client is not allowed to use token-exchange"))
	}

	// Get request parameter related token exchange.
	params, err := parseRequestParameter(requester)
	if err != nil {
		return err
	}

	// Check and grant scope.
	for _, scope := range requester.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
		requester.GrantScope(scope)
	}

	// Check and grant audience.
	if err := c.Config.GetAudienceStrategy(ctx)(client.GetAudience(), requester.GetRequestedAudience()); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("audience not match: %v", err))
	}
	for _, audience := range requester.GetRequestedAudience() {
		requester.GrantAudience(audience)
	}

	// Verify subject token.
	switch params.subjectTokenType {
	case tokenTypeIDToken:
		claims := jwt.MapClaims{}
		if _, err := jwt.ParseWithClaims(params.subjectToken, claims, c.keyFunc(ctx)); err != nil {
			return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("failed to verify JWT: %v", err))
		}
		subject, err := c.Storage.GetImpersonateSubject(ctx, claims, requester)
		if err != nil {
			return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("not allowed to token exchange by jwt: %v", err))
		}
		requester.SetSession(&fosite.DefaultSession{
			Subject: subject,
		})
		requester.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(c.HandleHelper.Config.GetAccessTokenLifespan(ctx)))
		return nil
	case tokenTypeAT:
		or, err := c.verifyAccessTokenAsSubjectToken(ctx, client.GetID(), params)
		if err != nil {
			return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("not allowed to token exchange by at: %v", err))
		}
		requester.SetSession(or.GetSession().Clone())
		// When the subject_type is AT, the expiration time is same with subject_token.
		// Therefore, we don't need to set the expiresAt.
		return nil
	default:
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("unsupported subject_type %s", params.subjectTokenType))
	}
}

func (c *Handler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	if !requester.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeTokenExchange)) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHintf("The OAuth 2.0 Client is not allowed to use authorization grant '%s'.", fosite.GrantTypeTokenExchange))
	}

	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeTokenExchange, fosite.AccessToken, c.HandleHelper.Config.GetAccessTokenLifespan(ctx))

	if err := c.IssueAccessToken(ctx, atLifespan, requester, responder); err != nil {
		return err
	}

	if canIssueRefreshToken(ctx, c, requester) {
		refresh, refreshSignature, err := c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
		if err := c.RefreshTokenStorage.CreateRefreshTokenSession(ctx, refreshSignature, requester); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
		}

		responder.SetExtra("refresh_token", refresh)
	}
	return nil
}

func canIssueRefreshToken(ctx context.Context, c *Handler, requester fosite.Requester) bool {
	scope := c.Config.GetRefreshTokenScopes(ctx)
	// Require one of the refresh token scopes, if set.
	if len(scope) > 0 && !requester.GetGrantedScopes().HasOneOf(scope...) {
		return false
	}
	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !requester.GetClient().GetGrantTypes().Has("refresh_token") {
		return false
	}
	return true
}

func (c *Handler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	if s := c.Config.GetGrantTypeTokenExchangeCanSkipClientAuth(ctx); s != nil {
		return s(ctx, requester)
	}

	return false
}

func (c *Handler) keyFunc(ctx context.Context) jwt.Keyfunc {
	return jwt.Keyfunc(func(t *jwt.Token) (interface{}, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, errors.New("invalid kid")
		}
		iss, ok := t.Claims["iss"].(string)
		if !ok {
			return nil, errors.New("invalid iss")
		}
		return c.Storage.GetIDTokenPublicKey(ctx, iss, kid)
	})
}

func (c *Handler) verifyAccessTokenAsSubjectToken(ctx context.Context, clientID string, params *tokenExchangeParams) (fosite.Requester, error) {
	sig := c.HandleHelper.AccessTokenStrategy.AccessTokenSignature(ctx, params.subjectToken)
	or, err := c.HandleHelper.AccessTokenStorage.GetAccessTokenSession(ctx, sig, nil)
	if err != nil {
		return nil, errorsx.WithStack(fosite.ErrRequestUnauthorized.WithWrap(err).WithDebug(err.Error()))
	} else if err := c.AccessTokenStrategy.ValidateAccessToken(ctx, or, params.subjectToken); err != nil {
		return nil, err
	}

	allowClientIDs, err := c.Storage.GetAllowedClientIDs(ctx, clientID)
	if err != nil {
		return nil, err
	}

	for _, cid := range allowClientIDs {
		if or.GetClient().GetID() == cid {
			return or, nil
		}
	}
	return nil, fmt.Errorf("this access_token is not allowed to use token exchange based on AT: original_client:%s, request_client:%s ", or.GetClient().GetID(), clientID)
}

func (c *Handler) CanHandleTokenEndpointRequest(requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeTokenExchange))
}
