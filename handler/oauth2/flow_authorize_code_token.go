// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/fosite/storage"
	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
)

type AuthorizeCodeHandler struct {
	AuthorizeCodeStrategy AuthorizeCodeStrategy
}

func (c AuthorizeCodeHandler) Code(ctx context.Context, requester fosite.AccessRequester) (string, string, error) {
	code := requester.GetRequestForm().Get("code")
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	return code, signature, nil
}

func (c AuthorizeCodeHandler) ValidateCode(ctx context.Context, requester fosite.Requester, code string) error {
	return nil
}

func (c AuthorizeCodeHandler) ValidateCodeSession(ctx context.Context, requester fosite.Requester, code string) error {
	return c.AuthorizeCodeStrategy.ValidateAuthorizeCode(ctx, requester, code)
}

type AuthorizeExplicitGrantSessionHandler struct {
	AuthorizeCodeStorage AuthorizeCodeStorage
}

func (s AuthorizeExplicitGrantSessionHandler) Session(ctx context.Context, requester fosite.AccessRequester, codeSignature string) (fosite.Requester, error) {
	req, err := s.AuthorizeCodeStorage.GetAuthorizeCodeSession(ctx, codeSignature, requester.GetSession())

	if err != nil && errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) {
		if req != nil {
			return req, err
		}

		return req, fosite.ErrServerError.
			WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
			WithDebug("\"GetAuthorizeCodeSession\" must return a value for \"fosite.Requester\" when returning \"ErrInvalidatedAuthorizeCode\".")
	}

	if err != nil && errors.Is(err, fosite.ErrNotFound) {
		return nil, errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
	}

	if err != nil {
		return nil, errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return req, err
}

func (s AuthorizeExplicitGrantSessionHandler) InvalidateSession(ctx context.Context, codeSignature string) error {
	return s.AuthorizeCodeStorage.InvalidateAuthorizeCodeSession(ctx, codeSignature)
}

type AuthorizeExplicitGrantAccessRequestValidator struct{}

func (v AuthorizeExplicitGrantAccessRequestValidator) CanHandleRequest(requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne("authorization_code")
}

func (v AuthorizeExplicitGrantAccessRequestValidator) ValidateGrantTypes(requester fosite.AccessRequester) error {
	if !requester.GetClient().GetGrantTypes().Has("authorization_code") {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"authorization_code\"."))
	}

	return nil
}

func (v AuthorizeExplicitGrantAccessRequestValidator) ValidateRedirectURI(accessRequester fosite.AccessRequester, authorizeRequester fosite.Requester) error {
	forcedRedirectURI := authorizeRequester.GetRequestForm().Get("redirect_uri")
	requestedRedirectURI := accessRequester.GetRequestForm().Get("redirect_uri")
	if forcedRedirectURI != "" && forcedRedirectURI != requestedRedirectURI {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The \"redirect_uri\" from this request does not match the one from the authorize request."))
	}

	return nil
}

type AuthorizeExplicitTokenEndpointHandler struct {
	GenericCodeTokenEndpointHandler
}

func (c *AuthorizeExplicitGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	code := requester.GetRequestForm().Get("code")
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	authorizeRequest, err := c.CoreStorage.GetAuthorizeCodeSession(ctx, signature, requester.GetSession())
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err := c.AuthorizeCodeStrategy.ValidateAuthorizeCode(ctx, requester, code); err != nil {
		// This needs to happen after store retrieval for the session to be hydrated properly
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithWrap(err).WithDebug(err.Error()))
	}

	for _, scope := range authorizeRequest.GetGrantedScopes() {
		requester.GrantScope(scope)
	}

	for _, audience := range authorizeRequest.GetGrantedAudience() {
		requester.GrantAudience(audience)
	}

	access, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	var refresh, refreshSignature string
	if canIssueRefreshToken(ctx, c, authorizeRequest) {
		refresh, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	ctx, err = storage.MaybeBeginTx(ctx, c.CoreStorage)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	defer func() {
		if err != nil {
			if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.CoreStorage); rollBackTxnErr != nil {
				err = errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
			}
		}
	}()

	if err = c.CoreStorage.InvalidateAuthorizeCodeSession(ctx, signature); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err = c.CoreStorage.CreateAccessTokenSession(ctx, accessSignature, requester.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if refreshSignature != "" {
		if err = c.CoreStorage.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, requester.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	responder.SetAccessToken(access)
	responder.SetTokenType("bearer")
	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	if refresh != "" {
		responder.SetExtra("refresh_token", refresh)
	}

	if err = storage.MaybeCommitTx(ctx, c.CoreStorage); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}

func (c *AuthorizeExplicitGrantHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

func (c *AuthorizeExplicitGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "authorization_code"
	return requester.GetGrantTypes().ExactOne("authorization_code")
}

var (
	_ AccessRequestValidator      = (*AuthorizeExplicitGrantAccessRequestValidator)(nil)
	_ CodeHandler                 = (*AuthorizeCodeHandler)(nil)
	_ SessionHandler              = (*AuthorizeExplicitGrantSessionHandler)(nil)
	_ fosite.TokenEndpointHandler = (*AuthorizeExplicitTokenEndpointHandler)(nil)
)
