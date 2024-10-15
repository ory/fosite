// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package verifiable

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/storage"
	"github.com/ory/x/errorsx"
	"github.com/pkg/errors"
)

var _ fosite.TokenEndpointHandler = (*PreAuthorizeCodeTokenHandler)(nil)

type PreAuthorizeCodeTokenHandler struct {
	AuthorizeCodeStrategy  oauth2.AuthorizeCodeStrategy
	AccessTokenStrategy    oauth2.AccessTokenStrategy
	RefreshTokenStrategy   oauth2.RefreshTokenStrategy
	TokenRevocationStorage oauth2.TokenRevocationStorage
	Storage                Storage
	Config                 interface {
		fosite.AccessTokenLifespanProvider
		fosite.RefreshTokenLifespanProvider
		fosite.ScopeStrategyProvider
		fosite.AudienceStrategyProvider
		fosite.RefreshTokenScopesProvider
	}
}

// HandleTokenEndpointRequest handles an authorize request. If the handler is not responsible for handling
// the request, this method should return ErrUnknownRequest and otherwise handle the request.
func (c *PreAuthorizeCodeTokenHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest))
	}

	client := request.GetClient()

	// Check whether client is allowed to use pre-authorize grant type
	if !client.GetGrantTypes().Has(string(fosite.GrantTypePreAuthorizeCode)) {
		return errors.WithStack(fosite.ErrUnauthorizedClient.WithHintf(
			"The OAuth 2.0 Client is not allowed to use authorization grant \"%s\".", fosite.GrantTypePreAuthorizeCode))
	}

	// Check scope requested
	for _, scope := range request.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errors.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	// Check audience requested
	if err := c.Config.GetAudienceStrategy(ctx)(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	// load the session based on incoming pre-authorize_code request parameter
	code := request.GetRequestForm().Get("pre-authorized_code")

	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	preAuthRequest, err := c.Storage.GetPreAuthorizeCodeSession(ctx, signature, request.GetSession())
	if err != nil && errors.Is(err, fosite.ErrNotFound) {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("Invalid Pre-Authorized Code or the Pre-Authorized Code has expired."))
	} else if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// The authorization server MUST verify that the pre-authorization code is valid
	// This needs to happen after store retrieval for the session to be hydrated properly
	if err := c.AuthorizeCodeStrategy.ValidateAuthorizeCode(ctx, request, code); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
	}

	// Check transaction code
	incomingTxCode := request.GetRequestForm().Get("tx_code")
	expectedTxCode := preAuthRequest.GetTxCode()

	if len(expectedTxCode) == 0 && len(incomingTxCode) > 0 {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Transaction Code is not required."))
	} else if len(expectedTxCode) > 0 && len(incomingTxCode) == 0 {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Transaction Code is required."))
	} else if expectedTxCode != incomingTxCode {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("Transaction Code is mismatched."))
	}

	// Check whether user has authenticate the request
	if preAuthRequest.GetUserAuthenticationStatus() != fosite.UserAuthenticationApproved {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("User has not been authenticated yet."))
	}

	// Copy necessary things from original pre-authorize request
	request.SetSession(preAuthRequest.GetSession())
	request.SetID(preAuthRequest.GetID())

	atLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypePreAuthorizeCode, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	return nil
}

// PopulateTokenEndpointResponse is responsible for setting return values and should only be executed if
// the handler's HandleTokenEndpointRequest did not return ErrUnknownRequest.
func (c *PreAuthorizeCodeTokenHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	ctx, err := storage.MaybeBeginTx(ctx, c.TokenRevocationStorage)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	defer func() {
		if err != nil {
			if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.TokenRevocationStorage); rollBackTxnErr != nil {
				err = errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
			}
		}
	}()

	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(c.Config.GetAccessTokenLifespan(ctx)).Round(time.Second))
	access, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, request)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err := c.TokenRevocationStorage.CreateAccessTokenSession(ctx, accessSignature, request.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	var refresh, refreshSignature string
	if c.canIssueRefreshToken(ctx, request) {
		request.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(c.Config.GetRefreshTokenLifespan(ctx)).Round(time.Second))
		refresh, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, request)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		} else if err = c.TokenRevocationStorage.CreateRefreshTokenSession(ctx, refreshSignature, request.Sanitize([]string{})); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	if err = storage.MaybeCommitTx(ctx, c.TokenRevocationStorage); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	response.SetAccessToken(access)
	response.SetTokenType("bearer")
	atLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypePreAuthorizeCode, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	response.SetExpiresIn(getExpiresIn(request, fosite.AccessToken, atLifespan, time.Now().UTC()))
	response.SetScopes(request.GetGrantedScopes())
	if refresh != "" {
		response.SetExtra("refresh_token", refresh)
	}
	return nil
}

// canIssueRefreshToken is used to check whether to generate refresh token
func (c *PreAuthorizeCodeTokenHandler) canIssueRefreshToken(ctx context.Context, request fosite.Requester) bool {
	// Require one of the refresh token scopes, if set.
	scopes := c.Config.GetRefreshTokenScopes(ctx)
	if len(scopes) > 0 && !request.GetGrantedScopes().HasOneOf(scopes...) {
		return false
	}
	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return false
	}
	return true
}

// CanSkipClientAuth indicates if client authentication can be skipped. By default it MUST be false, unless you are
// implementing extension grant type, which allows unauthenticated client. CanSkipClientAuth must be called
// before HandleTokenEndpointRequest to decide, if AccessRequester will contain authenticated client.
func (c *PreAuthorizeCodeTokenHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	// the specification mentioned that client authentication is optional
	// however, for this implementation we requires it.
	return false
}

// CanHandleRequest indicates, if TokenEndpointHandler can handle this request or not. If true,
// HandleTokenEndpointRequest can be called.
func (c *PreAuthorizeCodeTokenHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	return requester.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:pre-authorized_code")
}

func getExpiresIn(r fosite.Requester, key fosite.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}
	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}
