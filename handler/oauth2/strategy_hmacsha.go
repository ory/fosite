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
	"math/rand"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
	enigma "github.com/ory/fosite/token/hmac"
)

type HMACSHAStrategy struct {
	Enigma                *enigma.HMACStrategy
	AccessTokenLifespan   time.Duration
	RefreshTokenLifespan  time.Duration
	AuthorizeCodeLifespan time.Duration
	DeviceCodeLifespan    time.Duration
	UserCodeLifeSpan      time.Duration
}

func (h HMACSHAStrategy) AccessTokenSignature(token string) string {
	return h.Enigma.Signature(token)
}

func (h HMACSHAStrategy) DeviceCodeSignature(token string) string {
	return h.Enigma.Signature(token)
}

func (h HMACSHAStrategy) UserCodeSignature(token string) string {
	return token
}

func (h HMACSHAStrategy) RefreshTokenSignature(token string) string {
	return h.Enigma.Signature(token)
}
func (h HMACSHAStrategy) AuthorizeCodeSignature(token string) string {
	return h.Enigma.Signature(token)
}

func (h HMACSHAStrategy) GenerateAccessToken(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

func (h HMACSHAStrategy) ValidateAccessToken(_ context.Context, r fosite.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.AccessToken)
	if exp.IsZero() && r.GetRequestedAt().Add(h.AccessTokenLifespan).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Access token expired at '%s'.", r.GetRequestedAt().Add(h.AccessTokenLifespan)))
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Access token expired at '%s'.", exp))
	}
	return h.Enigma.Validate(token)
}

func (h HMACSHAStrategy) GenerateRefreshToken(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

func (h HMACSHAStrategy) ValidateRefreshToken(_ context.Context, r fosite.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.RefreshToken)
	if exp.IsZero() {
		// Unlimited lifetime
		return h.Enigma.Validate(token)
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Refresh token expired at '%s'.", exp))
	}
	return h.Enigma.Validate(token)
}

func (h HMACSHAStrategy) GenerateAuthorizeCode(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

func (h HMACSHAStrategy) ValidateAuthorizeCode(_ context.Context, r fosite.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.AuthorizeCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.AuthorizeCodeLifespan).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Authorize code expired at '%s'.", r.GetRequestedAt().Add(h.AuthorizeCodeLifespan)))
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Authorize code expired at '%s'.", exp))
	}

	return h.Enigma.Validate(token)
}

// GenerateDeviceCode generates a new unique code for a device
func (h HMACSHAStrategy) GenerateDeviceCode(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

// ValidateDeviceCode checks the validity of the provided device code, returning an error if invalid
func (h HMACSHAStrategy) ValidateDeviceCode(_ context.Context, r fosite.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.DeviceCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.DeviceCodeLifespan).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Device code expired at '%s'.", r.GetRequestedAt().Add(h.DeviceCodeLifespan)))
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Device code expired at '%s'.", exp))
	}

	return h.Enigma.Validate(token)
}

func (h HMACSHAStrategy) GenerateUserCode(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	length := 6
	base20 := [20]byte{'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Z'}
	rand.Seed(time.Now().Unix())

	code := make([]byte, length)
	for i := 0; i < length; i++ {
		code[i] = base20[rand.Intn(len(base20))]
	}
	return string(code), string(code), nil
}

func (h HMACSHAStrategy) ValidateUserCode(_ context.Context, r fosite.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.UserCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.DeviceCodeLifespan).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("User code expired at '%s'.", r.GetRequestedAt().Add(h.DeviceCodeLifespan)))
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("User code expired at '%s'.", exp))
	}

	return h.Enigma.Validate(token)
}
