// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"github.com/ory/x/errorsx"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
)

type TokenRevocationHandler struct {
	TokenRevocationStorage TokenRevocationStorage
	RefreshTokenStrategy   RefreshTokenStrategy
	AccessTokenStrategy    AccessTokenStrategy

	// RevokeRefreshTokenOnRequestOnly is used to indicate if the refresh token should be revoked only if
	// token passed to the request is a refresh token. The default behavior revokes both the access and refresh
	// tokens if the token passed to the request is either.
	//
	// [RFC7009 - Section 2.1] Depending on the authorization server's revocation policy, the
	// revocation of a particular token may cause the revocation of related
	// tokens and the underlying authorization grant.  If the particular
	// token is a refresh token and the authorization server supports the
	// revocation of access tokens, then the authorization server SHOULD
	// also invalidate all access tokens based on the same authorization
	// grant (see Implementation Note).  If the token passed to the request
	// is an access token, the server MAY revoke the respective refresh
	// token as well.
	RevokeRefreshTokenOnRequestOnly bool
}

// RevokeToken implements https://tools.ietf.org/html/rfc7009#section-2.1
// The token type hint indicates which token type check should be performed first.
func (r *TokenRevocationHandler) RevokeToken(ctx context.Context, token string, tokenType fosite.TokenType, client fosite.Client) error {
	actualTokenType := tokenType
	discoveryFuncs := []func() (request fosite.Requester, err error){
		func() (request fosite.Requester, err error) {
			// Refresh token
			signature := r.RefreshTokenStrategy.RefreshTokenSignature(ctx, token)
			ar, err := r.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, nil)
			if err == nil {
				actualTokenType = fosite.RefreshToken
			}

			return ar, err
		},
		func() (request fosite.Requester, err error) {
			// Access token
			signature := r.AccessTokenStrategy.AccessTokenSignature(ctx, token)
			ar, err := r.TokenRevocationStorage.GetAccessTokenSession(ctx, signature, nil)
			if err == nil {
				actualTokenType = fosite.AccessToken
			}

			return ar, err
		},
	}

	// Token type hinting
	if tokenType == fosite.AccessToken {
		discoveryFuncs[0], discoveryFuncs[1] = discoveryFuncs[1], discoveryFuncs[0]
	}

	var ar fosite.Requester
	var err1, err2 error
	if ar, err1 = discoveryFuncs[0](); err1 != nil {
		ar, err2 = discoveryFuncs[1]()
	}
	// err2 can only be not nil if first err1 was not nil
	if err2 != nil {
		return storeErrorsToRevocationError(err1, err2)
	}

	if ar.GetClient().GetID() != client.GetID() {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient)
	}

	requestID := ar.GetID()
	if !r.RevokeRefreshTokenOnRequestOnly || actualTokenType == fosite.RefreshToken {
		err1 = r.TokenRevocationStorage.RevokeRefreshToken(ctx, requestID)
	}

	err2 = r.TokenRevocationStorage.RevokeAccessToken(ctx, requestID)

	return storeErrorsToRevocationError(err1, err2)
}

func storeErrorsToRevocationError(err1, err2 error) error {
	// both errors are fosite.ErrNotFound and fosite.ErrInactiveToken or nil <=> the token is revoked
	if (errors.Is(err1, fosite.ErrNotFound) || errors.Is(err1, fosite.ErrInactiveToken) || err1 == nil) &&
		(errors.Is(err2, fosite.ErrNotFound) || errors.Is(err2, fosite.ErrInactiveToken) || err2 == nil) {
		return nil
	}

	// there was an unexpected error => the token may still exist and the client should retry later
	return errorsx.WithStack(fosite.ErrTemporarilyUnavailable)
}
