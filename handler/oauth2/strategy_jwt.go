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
	"strings"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

// DefaultJWTStrategy is a JWT RS256 strategy.
type DefaultJWTStrategy struct {
	jwt.JWTStrategy
	HMACSHAStrategy *HMACSHAStrategy
	Issuer          string
	ScopeField      jwt.JWTScopeFieldEnum
}

func (h *DefaultJWTStrategy) WithIssuer(issuer string) *DefaultJWTStrategy {
	h.Issuer = issuer
	return h
}

func (h *DefaultJWTStrategy) WithScopeField(scopeField jwt.JWTScopeFieldEnum) *DefaultJWTStrategy {
	h.ScopeField = scopeField
	return h
}

func (h DefaultJWTStrategy) signature(token string) string {
	split := strings.Split(token, ".")
	if len(split) != 3 {
		return ""
	}

	return split[2]
}

func (h DefaultJWTStrategy) AccessTokenSignature(token string) string {
	return h.signature(token)
}

func (h *DefaultJWTStrategy) GenerateAccessToken(ctx context.Context, requester fosite.Requester) (token string, signature string, err error) {
	return h.generate(ctx, fosite.AccessToken, requester)
}

func (h *DefaultJWTStrategy) ValidateAccessToken(ctx context.Context, _ fosite.Requester, token string) error {
	_, err := validate(ctx, h.JWTStrategy, token)
	return err
}

func (h DefaultJWTStrategy) RefreshTokenSignature(token string) string {
	return h.HMACSHAStrategy.RefreshTokenSignature(token)
}

func (h DefaultJWTStrategy) AuthorizeCodeSignature(token string) string {
	return h.HMACSHAStrategy.AuthorizeCodeSignature(token)
}

func (h *DefaultJWTStrategy) GenerateRefreshToken(ctx context.Context, req fosite.Requester) (token string, signature string, err error) {
	return h.HMACSHAStrategy.GenerateRefreshToken(ctx, req)
}

func (h *DefaultJWTStrategy) ValidateRefreshToken(ctx context.Context, req fosite.Requester, token string) error {
	return h.HMACSHAStrategy.ValidateRefreshToken(ctx, req, token)
}

func (h *DefaultJWTStrategy) GenerateAuthorizeCode(ctx context.Context, req fosite.Requester) (token string, signature string, err error) {
	return h.HMACSHAStrategy.GenerateAuthorizeCode(ctx, req)
}

func (h *DefaultJWTStrategy) ValidateAuthorizeCode(ctx context.Context, req fosite.Requester, token string) error {
	return h.HMACSHAStrategy.ValidateAuthorizeCode(ctx, req, token)
}

func validate(ctx context.Context, jwtStrategy jwt.JWTStrategy, token string) (t *jwt.Token, err error) {
	t, err = jwtStrategy.Decode(ctx, token)

	if err == nil {
		err = t.Claims.Valid()
	}

	if err != nil {
		var e *jwt.ValidationError
		if errors.As(err, &e) {
			switch e.Errors {
			case jwt.ValidationErrorMalformed:
				err = errorsx.WithStack(fosite.ErrInvalidTokenFormat.WithWrap(err).WithDebug(err.Error()))
			case jwt.ValidationErrorUnverifiable:
				err = errorsx.WithStack(fosite.ErrTokenSignatureMismatch.WithWrap(err).WithDebug(err.Error()))
			case jwt.ValidationErrorSignatureInvalid:
				err = errorsx.WithStack(fosite.ErrTokenSignatureMismatch.WithWrap(err).WithDebug(err.Error()))
			case jwt.ValidationErrorAudience:
				err = errorsx.WithStack(fosite.ErrTokenClaim.WithWrap(err).WithDebug(err.Error()))
			case jwt.ValidationErrorExpired:
				err = errorsx.WithStack(fosite.ErrTokenExpired.WithWrap(err).WithDebug(err.Error()))
			case jwt.ValidationErrorIssuedAt:
				err = errorsx.WithStack(fosite.ErrTokenClaim.WithWrap(err).WithDebug(err.Error()))
			case jwt.ValidationErrorIssuer:
				err = errorsx.WithStack(fosite.ErrTokenClaim.WithWrap(err).WithDebug(err.Error()))
			case jwt.ValidationErrorNotValidYet:
				err = errorsx.WithStack(fosite.ErrTokenClaim.WithWrap(err).WithDebug(err.Error()))
			case jwt.ValidationErrorId:
				err = errorsx.WithStack(fosite.ErrTokenClaim.WithWrap(err).WithDebug(err.Error()))
			case jwt.ValidationErrorClaimsInvalid:
				err = errorsx.WithStack(fosite.ErrTokenClaim.WithWrap(err).WithDebug(err.Error()))
			default:
				err = errorsx.WithStack(fosite.ErrRequestUnauthorized.WithWrap(err).WithDebug(err.Error()))
			}
		}
	}

	return
}

func (h *DefaultJWTStrategy) generate(ctx context.Context, tokenType fosite.TokenType, requester fosite.Requester) (string, string, error) {
	if jwtSession, ok := requester.GetSession().(JWTSessionContainer); !ok {
		return "", "", errors.Errorf("Session must be of type JWTSessionContainer but got type: %T", requester.GetSession())
	} else if jwtSession.GetJWTClaims() == nil {
		return "", "", errors.New("GetTokenClaims() must not be nil")
	} else {
		claims := jwtSession.GetJWTClaims().
			With(
				jwtSession.GetExpiresAt(tokenType),
				requester.GetGrantedScopes(),
				requester.GetGrantedAudience(),
			).
			WithDefaults(
				time.Now().UTC(),
				h.Issuer,
			).
			WithScopeField(
				h.ScopeField,
			)

		return h.JWTStrategy.Generate(ctx, claims.ToMapClaims(), jwtSession.GetJWTHeader())
	}
}
