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
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
	enigma "github.com/ory/fosite/token/hmac"
)

type HMACSHAStrategy struct {
	Enigma *enigma.HMACStrategy
	Config interface {
		fosite.AccessTokenLifespanProvider
		fosite.RefreshTokenLifespanProvider
		fosite.AuthorizeCodeLifespanProvider
		fosite.DeviceAndUserCodeLifespanProvider
	}
	prefix *string
}

func (h *HMACSHAStrategy) AccessTokenSignature(ctx context.Context, token string) string {
	return h.Enigma.Signature(token)
}
func (h *HMACSHAStrategy) RefreshTokenSignature(ctx context.Context, token string) string {
	return h.Enigma.Signature(token)
}
func (h *HMACSHAStrategy) AuthorizeCodeSignature(ctx context.Context, token string) string {
	return h.Enigma.Signature(token)
}

func (h *HMACSHAStrategy) getPrefix(part string) string {
	if h.prefix == nil {
		prefix := "ory_%s_"
		h.prefix = &prefix
	} else if len(*h.prefix) == 0 {
		return ""
	}

	return fmt.Sprintf(*h.prefix, part)
}

func (h *HMACSHAStrategy) trimPrefix(token, part string) string {
	return strings.TrimPrefix(token, h.getPrefix(part))
}

func (h *HMACSHAStrategy) setPrefix(token, part string) string {
	return h.getPrefix(part) + token
}

func (h *HMACSHAStrategy) GenerateAccessToken(ctx context.Context, _ fosite.Requester) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return h.setPrefix(token, "at"), sig, nil
}

func (h *HMACSHAStrategy) ValidateAccessToken(ctx context.Context, r fosite.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.AccessToken)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetAccessTokenLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Access token expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetAccessTokenLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Access token expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(token, "at"))
}

func (h *HMACSHAStrategy) GenerateRefreshToken(ctx context.Context, _ fosite.Requester) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return h.setPrefix(token, "rt"), sig, nil
}

func (h *HMACSHAStrategy) ValidateRefreshToken(ctx context.Context, r fosite.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.RefreshToken)
	if exp.IsZero() {
		// Unlimited lifetime
		return h.Enigma.Validate(ctx, h.trimPrefix(token, "rt"))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Refresh token expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(token, "rt"))
}

func (h *HMACSHAStrategy) GenerateAuthorizeCode(ctx context.Context, _ fosite.Requester) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return h.setPrefix(token, "ac"), sig, nil
}

func (h *HMACSHAStrategy) ValidateAuthorizeCode(ctx context.Context, r fosite.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.AuthorizeCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetAuthorizeCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Authorize code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetAuthorizeCodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Authorize code expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(token, "ac"))
}

func (h HMACSHAStrategy) generateRandomString(length int) (token string, err error) {
	chars := [20]byte{'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Z'}
	chars_length := int64(len(chars))

	code := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(chars_length))
		if err != nil {
			return "", err
		}
		code[i] = chars[num.Int64()]
	}
	return string(code), nil
}

func (h HMACSHAStrategy) GenerateUserCode() (token string, err error) {
	return h.generateRandomString(8)
}

func (h HMACSHAStrategy) UserCodeSignature(ctx context.Context, token string) string {
	return h.Enigma.GenerateHMACForString(token, ctx)
}

func (h HMACSHAStrategy) ValidateUserCode(ctx context.Context, r fosite.Requester, code string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.UserCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Access token expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx))))
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Access token expired at '%s'.", exp))
	}
	return nil
}

func (h HMACSHAStrategy) GenerateDeviceCode() (token string, err error) {
	return h.generateRandomString(100)
}

func (h HMACSHAStrategy) DeviceCodeSignature(ctx context.Context, token string) string {
	return h.Enigma.GenerateHMACForString(token, ctx)
}

func (h HMACSHAStrategy) ValidateDeviceCode(ctx context.Context, r fosite.Requester, code string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.UserCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("1 Device code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx))))
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("2 Device code expired at '%s'.", exp))
	}
	return nil
}
