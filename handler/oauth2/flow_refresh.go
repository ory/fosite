// Copyright © 2017 Aeneas Rekkas <aeneas+oss@aeneas.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oauth2

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/pkg/errors"
)

type RefreshTokenGrantHandler struct {
	AccessTokenStrategy    AccessTokenStrategy
	RefreshTokenStrategy   RefreshTokenStrategy
	TokenRevocationStorage TokenRevocationStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	// grant_type REQUIRED.
	// Value MUST be set to "refresh_token".
	if !request.GetGrantTypes().Exact("refresh_token") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return errors.WithStack(fosite.ErrInvalidGrant.WithDebug("The client is not allowed to use grant type refresh_token"))
	}

	refresh := request.GetRequestForm().Get("refresh_token")

	signature := c.RefreshTokenStrategy.RefreshTokenSignature(refresh)
	originalRequest, err := c.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, request.GetSession())
	if errors.Cause(err) == fosite.ErrNotFound {
		return errors.WithStack(fosite.ErrInvalidRequest.WithDebug(err.Error()))
	} else if err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	} else if err := c.RefreshTokenStrategy.ValidateRefreshToken(ctx, request, refresh); err != nil {
		// The authorization server MUST ... validate the refresh token.
		// This needs to happen after store retrieval for the session to be hydrated properly
		return errors.WithStack(fosite.ErrInvalidRequest.WithDebug(err.Error()))
	}

	if !originalRequest.GetGrantedScopes().HasOneOf("offline", "offline_access") {
		return errors.WithStack(fosite.ErrScopeNotGranted.WithDebug("The client is not allowed to use grant type refresh_token"))

	}

	// The authorization server MUST ... and ensure that the refresh token was issued to the authenticated client
	if originalRequest.GetClient().GetID() != request.GetClient().GetID() {
		return errors.WithStack(fosite.ErrInvalidRequest.WithDebug("Client ID mismatch"))
	}

	request.SetSession(originalRequest.GetSession().Clone())
	request.SetRequestedScopes(originalRequest.GetRequestedScopes())
	for _, scope := range originalRequest.GetGrantedScopes() {
		request.GrantScope(scope)
	}

	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(c.AccessTokenLifespan))
	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !requester.GetGrantTypes().Exact("refresh_token") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	accessToken, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	}

	refreshToken, refreshSignature, err := c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
	if err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	}

	signature := c.RefreshTokenStrategy.RefreshTokenSignature(requester.GetRequestForm().Get("refresh_token"))
	if ts, err := c.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, nil); err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	} else if err := c.TokenRevocationStorage.RevokeAccessToken(ctx, ts.GetID()); err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	} else if err := c.TokenRevocationStorage.RevokeRefreshToken(ctx, ts.GetID()); err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	} else if err := c.TokenRevocationStorage.CreateAccessTokenSession(ctx, accessSignature, requester); err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	} else if err := c.TokenRevocationStorage.CreateRefreshTokenSession(ctx, refreshSignature, requester); err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	}

	responder.SetAccessToken(accessToken)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, c.AccessTokenLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	responder.SetExtra("refresh_token", refreshToken)
	return nil
}
