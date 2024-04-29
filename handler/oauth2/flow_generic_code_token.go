// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/fosite/storage"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
)

// AccessRequestValidator handles various validations in the access request handling.
type AccessRequestValidator interface {
	// CanHandleRequest validates if the access request should be handled.
	CanHandleRequest(requester fosite.AccessRequester) bool

	// ValidateGrantTypes validates the grant types in the access request.
	ValidateGrantTypes(requester fosite.AccessRequester) error

	// ValidateRedirectURI validates the redirect uri in the access request.
	ValidateRedirectURI(accessRequester fosite.AccessRequester, authorizeRequester fosite.Requester) error

	// GetGrantType retrieves the grant type from the request.
	GetGrantType(requester fosite.AccessRequester) fosite.GrantType
}

// CodeHandler handles authorization/device code related operations.
type CodeHandler interface {
	// Code fetches the code and code signature.
	Code(ctx context.Context, requester fosite.AccessRequester) (code string, signature string, err error)

	// ValidateCode validates the code. Can be used for checks that need to run before we fetch the session from the database.
	ValidateCode(ctx context.Context, requester fosite.Requester, code string) error

	// ValidateCodeSession validates the code session.
	ValidateCodeSession(ctx context.Context, requester fosite.Requester, code string) error
}

// SessionHandler handles session-related operations.
type SessionHandler interface {
	// Session fetches the authorized request.
	Session(ctx context.Context, requester fosite.AccessRequester, codeSignature string) (fosite.Requester, error)

	// InvalidateSession invalidates the code and session.
	InvalidateSession(ctx context.Context, codeSignature string) error
}

// GenericCodeTokenEndpointHandler is a token response handler for
// - the Authorize Code grant using the explicit grant type as defined in https://tools.ietf.org/html/rfc6749#section-4.1
// - the Device Authorization Grant as defined in https://www.rfc-editor.org/rfc/rfc8628
type GenericCodeTokenEndpointHandler struct {
	AccessRequestValidator
	CodeHandler
	SessionHandler

	AccessTokenStrategy    AccessTokenStrategy
	RefreshTokenStrategy   RefreshTokenStrategy
	CoreStorage            CoreStorage
	TokenRevocationStorage TokenRevocationStorage
	Config                 interface {
		fosite.AccessTokenLifespanProvider
		fosite.RefreshTokenLifespanProvider
		fosite.RefreshTokenScopesProvider
	}
}

func (c *GenericCodeTokenEndpointHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	var code, signature string
	var err error
	if code, signature, err = c.Code(ctx, requester); err != nil {
		return err
	}

	var ar fosite.Requester
	if ar, err = c.Session(ctx, requester, signature); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if err = c.ValidateCodeSession(ctx, ar, code); err != nil {
		return errorsx.WithStack(err)
	}

	for _, scope := range ar.GetGrantedScopes() {
		requester.GrantScope(scope)
	}

	for _, audience := range ar.GetGrantedAudience() {
		requester.GrantAudience(audience)
	}

	var accessToken, accessTokenSignature string
	accessToken, accessTokenSignature, err = c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	var refreshToken, refreshTokenSignature string
	if c.canIssueRefreshToken(ctx, requester) {
		refreshToken, refreshTokenSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
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

	if err = c.InvalidateSession(ctx, signature); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if err = c.CoreStorage.CreateAccessTokenSession(ctx, accessTokenSignature, requester.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if refreshTokenSignature != "" {
		if err = c.CoreStorage.CreateRefreshTokenSession(ctx, refreshTokenSignature, requester.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	lifeSpan := fosite.GetEffectiveLifespan(requester.GetClient(), c.GetGrantType(requester), fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	responder.SetAccessToken(accessToken)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, lifeSpan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	if refreshToken != "" {
		responder.SetExtra("refresh_token", refreshToken)
	}

	if err = storage.MaybeCommitTx(ctx, c.CoreStorage); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}

func (c *GenericCodeTokenEndpointHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest))
	}

	var err error
	if err = c.ValidateGrantTypes(requester); err != nil {
		return err
	}

	var code, signature string
	if code, signature, err = c.Code(ctx, requester); err != nil {
		return err
	}

	if err = c.ValidateCode(ctx, requester, code); err != nil {
		return errorsx.WithStack(err)
	}

	var ar fosite.Requester
	if ar, err = c.Session(ctx, requester, signature); err != nil {
		if ar != nil && (errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) || errors.Is(err, fosite.ErrInvalidatedDeviceCode)) {
			return c.revokeTokens(ctx, requester.GetID())
		}

		return err
	}

	if err = c.ValidateCodeSession(ctx, ar, code); err != nil {
		return errorsx.WithStack(err)
	}

	// Override scopes
	requester.SetRequestedScopes(ar.GetRequestedScopes())

	// Override audiences
	requester.SetRequestedAudience(ar.GetRequestedAudience())

	// The authorization server MUST ensure that
	// the authorization code was issued to the authenticated confidential client,
	// or if the client is public, ensure that the code was issued to "client_id" in the request
	if ar.GetClient().GetID() != requester.GetClient().GetID() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	if err = c.ValidateRedirectURI(requester, ar); err != nil {
		return err
	}

	// Checking of POST client_id skipped, because
	// if the client type is confidential or the client was issued client credentials (or assigned other authentication requirements),
	// the client MUST authenticate with the authorization server as described in Section 3.2.1.
	requester.SetSession(ar.GetSession())
	requester.SetID(ar.GetID())

	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), c.GetGrantType(requester), fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	requester.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), c.GetGrantType(requester), fosite.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		requester.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	return nil
}

func (c *GenericCodeTokenEndpointHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

func (c *GenericCodeTokenEndpointHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	return c.CanHandleRequest(requester)
}

func (c *GenericCodeTokenEndpointHandler) canIssueRefreshToken(ctx context.Context, requester fosite.Requester) bool {
	scopes := c.Config.GetRefreshTokenScopes(ctx)

	// Require one of the refresh token scopes, if set.
	if len(scopes) > 0 && !requester.GetGrantedScopes().HasOneOf(scopes...) {
		return false
	}

	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !requester.GetClient().GetGrantTypes().Has("refresh_token") {
		return false
	}

	return true
}

func (c *GenericCodeTokenEndpointHandler) revokeTokens(ctx context.Context, reqId string) error {
	hint := "The authorization code has already been used."
	var debug strings.Builder

	revokeAndAppendErr := func(tokenType string, revokeFunc func(context.Context, string) error) {
		if err := revokeFunc(ctx, reqId); err != nil {
			hint += fmt.Sprintf(" Additionally, an error occurred during processing the %s token revocation.", tokenType)
			debug.WriteString(fmt.Sprintf("Revocation of %s token lead to error %s.", tokenType, err.Error()))
		}
	}

	revokeAndAppendErr("access", c.TokenRevocationStorage.RevokeAccessToken)
	revokeAndAppendErr("refresh", c.TokenRevocationStorage.RevokeRefreshToken)

	return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint(hint).WithDebug(debug.String()))
}

var _ fosite.TokenEndpointHandler = (*GenericCodeTokenEndpointHandler)(nil)
