/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

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
}

// RevokeToken implements https://tools.ietf.org/html/rfc7009#section-2.1
// The token type hint indicates which token type check should be performed first.
func (r *TokenRevocationHandler) RevokeToken(ctx context.Context, token string, tokenType fosite.TokenType, client fosite.Client) error {
	discoveryFuncs := []func() (request fosite.Requester, err error){
		func() (request fosite.Requester, err error) {
			// Refresh token
			signature := r.RefreshTokenStrategy.RefreshTokenSignature(ctx, token)
			return r.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, nil)
		},
		func() (request fosite.Requester, err error) {
			// Access token
			signature := r.AccessTokenStrategy.AccessTokenSignature(ctx, token)
			return r.TokenRevocationStorage.GetAccessTokenSession(ctx, signature, nil)
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
	err1 = r.TokenRevocationStorage.RevokeRefreshToken(ctx, requestID)
	err2 = r.TokenRevocationStorage.RevokeAccessToken(ctx, requestID)

	return storeErrorsToRevocationError(err1, err2)
}

func storeErrorsToRevocationError(err1, err2 error) error {
	// both errors are 404 or nil <=> the token is revoked
	if (errors.Is(err1, fosite.ErrNotFound) || err1 == nil) && (errors.Is(err2, fosite.ErrNotFound) || err2 == nil) {
		return nil
	}

	// there was an unexpected error => the token may still exist and the client should retry later
	return errorsx.WithStack(fosite.ErrTemporarilyUnavailable)
}
