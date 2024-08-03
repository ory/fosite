// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
	"github.com/ory/x/errorsx"
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
		switch at := requestedAtClaim.(type) {
		case float64:
			requestedAt = time.Unix(int64(at), 0).UTC()
		case int64:
			requestedAt = time.Unix(at, 0).UTC()
		}
	}

	clientId := ""
	clientIdClaim, ok := mapClaims["client_id"]
	if ok {
		switch cid := clientIdClaim.(type) {
		case string:
			clientId = cid
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

	if !IsJWTProfileAccessToken(t) {
		return "", errorsx.WithStack(fosite.ErrRequestUnauthorized.WithDebug("The provided token is not a valid RFC9068 JWT Profile Access Token as it is missing the header 'typ' value of 'at+jwt' "))
	}

	requester := AccessTokenJWTToRequest(t)

	if err := matchScopes(v.Config.GetScopeStrategy(ctx), requester.GetGrantedScopes(), scopes); err != nil {
		return fosite.AccessToken, err
	}

	accessRequest.Merge(requester)

	return fosite.AccessToken, nil
}

// IsJWTProfileAccessToken validates a *jwt.Token is actually a RFC9068 JWT Profile Access Token by checking the
// relevant header as per https://datatracker.ietf.org/doc/html/rfc9068#section-2.1 which explicitly states that
// the header MUST include a typ of 'at+jwt' or 'application/at+jwt' with a preference of 'at+jwt'.
func IsJWTProfileAccessToken(token *jwt.Token) bool {
	var (
		raw any
		typ string
		ok  bool
	)

	if token == nil {
		return false
	}

	if raw, ok = token.Header[string(jwt.JWTHeaderType)]; !ok {
		return false
	}

	typ, ok = raw.(string)

	return ok && (typ == "at+jwt" || typ == "application/at+jwt")
}
