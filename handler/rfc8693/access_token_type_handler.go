// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/storage"
	"github.com/ory/x/errorsx"
	"github.com/pkg/errors"
)

type AccessTokenTypeHandler struct {
	Config               fosite.RFC8693ConfigProvider
	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration
	RefreshTokenScopes   []string
	oauth2.CoreStrategy
	ScopeStrategy fosite.ScopeStrategy
	Storage
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *AccessTokenTypeHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	session, _ := request.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	form := request.GetRequestForm()
	if form.Get("subject_token_type") != AccessTokenType && form.Get("actor_token_type") != AccessTokenType {
		return nil
	}

	if form.Get("actor_token_type") == AccessTokenType {
		token := form.Get("actor_token")
		if _, unpacked, err := c.validate(ctx, request, token); err != nil {
			return err
		} else {
			session.SetActorToken(unpacked)
		}
	}

	if form.Get("subject_token_type") == AccessTokenType {
		token := form.Get("subject_token")
		if subjectTokenSession, unpacked, err := c.validate(ctx, request, token); err != nil {
			return err
		} else {
			session.SetSubjectToken(unpacked)
			session.SetSubject(subjectTokenSession.GetSubject())
		}
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *AccessTokenTypeHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, responder fosite.AccessResponder) error {

	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	session, _ := request.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	form := request.GetRequestForm()
	requestedTokenType := form.Get("requested_token_type")
	if requestedTokenType == "" {
		requestedTokenType = c.Config.GetDefaultRequestedTokenType(ctx)
	}

	if requestedTokenType != AccessTokenType {
		return nil
	}

	if err := c.issue(ctx, request, responder); err != nil {
		return err
	}

	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *AccessTokenTypeHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *AccessTokenTypeHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "password".
	return requester.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:token-exchange")
}

func (c *AccessTokenTypeHandler) validate(ctx context.Context, request fosite.AccessRequester, token string) (fosite.Session, map[string]interface{}, error) {

	session, _ := request.GetSession().(Session)
	if session == nil {
		return nil, nil, errorsx.WithStack(fosite.ErrServerError.WithDebug(
			"Failed to perform token exchange because the session is not of the right type."))
	}

	client := request.GetClient()

	sig := c.CoreStrategy.AccessTokenSignature(ctx, token)
	or, err := c.Storage.GetAccessTokenSession(ctx, sig, request.GetSession())
	if err != nil {
		return nil, nil, errors.WithStack(fosite.ErrInvalidRequest.WithHint("Token is not valid or has expired.").WithDebug(err.Error()))
	} else if err := c.CoreStrategy.ValidateAccessToken(ctx, or, token); err != nil {
		return nil, nil, err
	}

	subjectTokenClientID := or.GetClient().GetID()
	// forbid original subjects client to exchange its own token
	if client.GetID() == subjectTokenClientID {
		return nil, nil, errors.WithStack(fosite.ErrRequestForbidden.WithHint("Clients are not allowed to perform a token exchange on their own tokens."))
	}

	// Check if the client is allowed to exchange this token
	if subjectTokenClient, ok := or.GetClient().(Client); ok {
		allowed := subjectTokenClient.TokenExchangeAllowed(client)
		if !allowed {
			return nil, nil, errors.WithStack(fosite.ErrRequestForbidden.WithHintf(
				"The OAuth 2.0 client is not permitted to exchange a subject token issued to client %s", subjectTokenClientID))
		}
	}

	// Scope check
	for _, scope := range request.GetRequestedScopes() {
		if !c.ScopeStrategy(or.GetGrantedScopes(), scope) {
			return nil, nil, errors.WithStack(fosite.ErrInvalidScope.WithHintf("The subject token is not granted \"%s\" and so this scope cannot be requested.", scope))
		}
	}

	// Convert to flat session with only access token claims
	tokenObject := session.AccessTokenClaimsMap()
	tokenObject["client_id"] = or.GetClient().GetID()
	tokenObject["scope"] = or.GetGrantedScopes()
	tokenObject["aud"] = or.GetGrantedAudience()

	return or.GetSession(), tokenObject, nil
}

func (c *AccessTokenTypeHandler) issue(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(c.AccessTokenLifespan))

	token, signature, err := c.CoreStrategy.GenerateAccessToken(ctx, request)
	if err != nil {
		return err
	} else if err := c.Storage.CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})); err != nil {
		return err
	}

	issueRefreshToken := c.canIssueRefreshToken(request)
	if issueRefreshToken {
		request.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(c.RefreshTokenLifespan).Round(time.Second))
		refresh, refreshSignature, err := c.CoreStrategy.GenerateRefreshToken(ctx, request)
		if err != nil {
			return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
		}

		if refreshSignature != "" {
			if err := c.Storage.CreateRefreshTokenSession(ctx, refreshSignature, request.Sanitize([]string{})); err != nil {
				if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.Storage); rollBackTxnErr != nil {
					err = rollBackTxnErr
				}
				return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
			}
		}

		response.SetExtra("refresh_token", refresh)
	}

	response.SetAccessToken(token)
	response.SetTokenType("bearer")
	response.SetExpiresIn(c.getExpiresIn(request, fosite.AccessToken, c.AccessTokenLifespan, time.Now().UTC()))
	response.SetScopes(request.GetGrantedScopes())

	return nil
}

func (c *AccessTokenTypeHandler) canIssueRefreshToken(request fosite.Requester) bool {
	// Require one of the refresh token scopes, if set.
	if len(c.RefreshTokenScopes) > 0 && !request.GetGrantedScopes().HasOneOf(c.RefreshTokenScopes...) {
		return false
	}
	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return false
	}
	return true
}

func (c *AccessTokenTypeHandler) getExpiresIn(r fosite.Requester, key fosite.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}
	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}
