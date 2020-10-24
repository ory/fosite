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
	"time"

	jwtx "github.com/dgrijalva/jwt-go"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

type StatelessJWTValidator struct {
	jwt.JWTStrategy
	ScopeStrategy fosite.ScopeStrategy
}

func (v *StatelessJWTValidator) IntrospectToken(ctx context.Context, token string, tokenUse fosite.TokenUse, accessRequest fosite.AccessRequester, scopes []string) (fosite.TokenUse, error) {
	t, err := validate(ctx, v.JWTStrategy, token)
	if err != nil {
		return "", err
	}

	// TODO: From here we assume it is an access token, but how do we know it is really and that is not an ID token?

	mapClaims := t.Claims.(jwtx.MapClaims)
	claims := jwt.JWTClaims{}
	claims.FromMapClaims(mapClaims)

	// claims.Scope is what has been granted to the given JWT.
	if err := matchScopes(v.ScopeStrategy, claims.Scope, scopes); err != nil {
		return fosite.AccessToken, err
	}

	requestedAt := claims.IssuedAt
	rat, ok := mapClaims["rat"]
	if ok {
		switch rat.(type) {
		case float64:
			requestedAt = time.Unix(int64(rat.(float64)), 0).UTC()
		case int64:
			requestedAt = time.Unix(rat.(int64), 0).UTC()
		}
	}

	requester := &fosite.Request{
		ID:          accessRequest.GetID(),
		RequestedAt: requestedAt,
		// TODO: Should this client be the client which requested the introspection or the client which obtained the JWT?
		Client: accessRequest.GetClient(),
		// We do not really know which scopes were requested, so we set them to granted.
		RequestedScope: claims.Scope,
		GrantedScope:   claims.Scope,
		Form:           accessRequest.GetRequestForm(),
		// TODO: Is it OK that this is JWTSession or should we allow custom session objects?
		Session: &JWTSession{
			JWTClaims: &claims,
			JWTHeader: &jwt.Headers{
				Extra: t.Header,
			},
			ExpiresAt: map[fosite.TokenType]time.Time{
				fosite.AccessToken: claims.ExpiresAt,
			},
			Subject: claims.Subject,
			// TODO: What about username?
		},
		// We do not really know which audiences were requested, so we set them to granted.
		RequestedAudience: claims.Audience,
		GrantedAudience:   claims.Audience,
	}

	accessRequest.Merge(requester)

	return fosite.AccessToken, nil
}
