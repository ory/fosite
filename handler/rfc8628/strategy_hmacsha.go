// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"strings"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/ory/x/randx"
	"github.com/patrickmn/go-cache"
	"golang.org/x/time/rate"

	"github.com/ory/fosite"
	enigma "github.com/ory/fosite/token/hmac"
)

// DefaultDeviceStrategy implements the default device strategy
type DefaultDeviceStrategy struct {
	Enigma           *enigma.HMACStrategy
	RateLimiterCache *cache.Cache
	Config           interface {
		fosite.DeviceProvider
		fosite.DeviceAndUserCodeLifespanProvider
	}
}

var _ RFC8628CodeStrategy = (*DefaultDeviceStrategy)(nil)

// GenerateUserCode generates a user_code
func (h *DefaultDeviceStrategy) GenerateUserCode(ctx context.Context) (string, string, error) {
	seq, err := randx.RuneSequence(8, []rune(randx.AlphaUpper))
	if err != nil {
		return "", "", err
	}
	userCode := string(seq)
	signUserCode, signErr := h.UserCodeSignature(ctx, userCode)
	if signErr != nil {
		return "", "", err
	}
	return userCode, signUserCode, nil
}

// UserCodeSignature generates a user_code signature
func (h *DefaultDeviceStrategy) UserCodeSignature(ctx context.Context, token string) (string, error) {
	return h.Enigma.GenerateHMACForString(ctx, token)
}

// ValidateUserCode validates a user_code
func (h *DefaultDeviceStrategy) ValidateUserCode(ctx context.Context, r fosite.Requester, code string) error {
	exp := r.GetSession().GetExpiresAt(fosite.UserCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrDeviceExpiredToken.WithHintf("User code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx))))
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrDeviceExpiredToken.WithHintf("User code expired at '%s'.", exp))
	}
	return nil
}

// GenerateDeviceCode generates a device_code
func (h *DefaultDeviceStrategy) GenerateDeviceCode(ctx context.Context) (string, string, error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return "ory_dc_" + token, sig, nil
}

// DeviceCodeSignature generates a device_code signature
func (h *DefaultDeviceStrategy) DeviceCodeSignature(ctx context.Context, token string) (string, error) {
	return h.Enigma.Signature(token), nil
}

// ValidateDeviceCode validates a device_code
func (h *DefaultDeviceStrategy) ValidateDeviceCode(ctx context.Context, r fosite.Requester, code string) error {
	exp := r.GetSession().GetExpiresAt(fosite.DeviceCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrDeviceExpiredToken.WithHintf("Device code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrDeviceExpiredToken.WithHintf("Device code expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, strings.TrimPrefix(code, "ory_dc_"))
}

// ShouldRateLimit is used to decide whether a request should be rate-limited
func (h *DefaultDeviceStrategy) ShouldRateLimit(context context.Context, code string) bool {
	key := code + "_limiter"

	if x, found := h.RateLimiterCache.Get(key); found {
		return !x.(*rate.Limiter).Allow()
	}

	rateLimiter := rate.NewLimiter(
		rate.Every(
			h.Config.GetDeviceAuthTokenPollingInterval(context),
		),
		1,
	)

	h.RateLimiterCache.Set(key, rateLimiter, cache.DefaultExpiration)
	return false
}
