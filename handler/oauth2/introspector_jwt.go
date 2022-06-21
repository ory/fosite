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

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

type StatelessJWTValidator struct {
	jwt.Signer
	Config interface {
		fosite.ScopeStrategyProvider
	}
}

// AccessTokenJWTToRequest tries to reconstruct fosite.Request from a JWT.
func AccessTokenJWTToRequest(token *jwt.Token) fosite.Requester {
	mapClaims := token.Claims
	claims := jwt.JWTClaims{}
	claims.FromMapClaims(mapClaims)

	requestedAt := claims.IssuedAt
	requestedAtClaim, ok := mapClaims["rat"]
	if ok {
		switch requestedAtClaim.(type) {
		case float64:
			requestedAt = time.Unix(int64(requestedAtClaim.(float64)), 0).UTC()
		case int64:
			requestedAt = time.Unix(requestedAtClaim.(int64), 0).UTC()
		}
	}

	clientId := ""
	clientIdClaim, ok := mapClaims["client_id"]
	if ok {
		switch clientIdClaim.(type) {
		case string:
			clientId = clientIdClaim.(string)
		}
	}

	return &fosite.Request{
		RequestedAt: requestedAt,
		Client: &fosite.DefaultClient{
			ID: clientId,
		},
		// We do not really know which scopes were requested, so we set them to granted.
		RequestedScope: claims.Scope,
		GrantedScope:   claims.Scope,
		Session: &JWTSession{
			JWTClaims: &claims,
			JWTHeader: &jwt.Headers{
				Extra: token.Header,
			},
			ExpiresAt: map[fosite.TokenType]time.Time{
				fosite.AccessToken: claims.ExpiresAt,
			},
			Subject: claims.Subject,
		},
		// We do not really know which audiences were requested, so we set them to granted.
		RequestedAudience: claims.Audience,
		GrantedAudience:   claims.Audience,
	}
}

func (v *StatelessJWTValidator) IntrospectToken(ctx context.Context, token string, tokenUse fosite.TokenUse, accessRequest fosite.AccessRequester, scopes []string) (fosite.TokenUse, error) {
	t, err := validate(ctx, v.Signer, token)
	if err != nil {
		return "", err
	}

	// TODO: From here we assume it is an access token, but how do we know it is really and that is not an ID token?

	requester := AccessTokenJWTToRequest(t)

	if err := matchScopes(v.Config.GetScopeStrategy(ctx), requester.GetGrantedScopes(), scopes); err != nil {
		return fosite.AccessToken, err
	}

	accessRequest.Merge(requester)

	return fosite.AccessToken, nil
}
