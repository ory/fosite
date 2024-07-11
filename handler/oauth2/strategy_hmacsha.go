// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"strings"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
	enigma "github.com/ory/fosite/token/hmac"
	_ "unsafe"
)

type HMACSHAStrategy struct {
	Enigma *enigma.HMACStrategy
	Config interface {
		fosite.AccessTokenLifespanProvider
		fosite.RefreshTokenLifespanProvider
		fosite.AuthorizeCodeLifespanProvider
	}
}

type HMACPrefixFunc func(ctx context.Context, h *HMACSHAStrategy, part string) string

func (h *HMACSHAStrategy) AccessTokenSignature(ctx context.Context, token string) string {
	return h.Enigma.Signature(token)
}

func (h *HMACSHAStrategy) RefreshTokenSignature(ctx context.Context, token string) string {
	return h.Enigma.Signature(token)
}

func (h *HMACSHAStrategy) AuthorizeCodeSignature(ctx context.Context, token string) string {
	return h.Enigma.Signature(token)
}

func (h *HMACSHAStrategy) trimPrefix(ctx context.Context, token, part string) string {
	return strings.TrimPrefix(token, getPrefix(ctx, h, part))
}

func (h *HMACSHAStrategy) setPrefix(ctx context.Context, token, part string) string {
	return getPrefix(ctx, h, part) + token
}

func (h *HMACSHAStrategy) GenerateAccessToken(ctx context.Context, _ fosite.Requester) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return h.setPrefix(ctx, token, "at"), sig, nil
}

func (h *HMACSHAStrategy) ValidateAccessToken(ctx context.Context, r fosite.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.AccessToken)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetAccessTokenLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Access token expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetAccessTokenLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Access token expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(ctx, token, "at"))
}

func (h *HMACSHAStrategy) GenerateRefreshToken(ctx context.Context, _ fosite.Requester) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return h.setPrefix(ctx, token, "rt"), sig, nil
}

func (h *HMACSHAStrategy) ValidateRefreshToken(ctx context.Context, r fosite.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.RefreshToken)
	if exp.IsZero() {
		// Unlimited lifetime
		return h.Enigma.Validate(ctx, h.trimPrefix(ctx, token, "rt"))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Refresh token expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(ctx, token, "rt"))
}

func (h *HMACSHAStrategy) GenerateAuthorizeCode(ctx context.Context, _ fosite.Requester) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return h.setPrefix(ctx, token, "ac"), sig, nil
}

func (h *HMACSHAStrategy) ValidateAuthorizeCode(ctx context.Context, r fosite.Requester, token string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.AuthorizeCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetAuthorizeCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Authorize code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetAuthorizeCodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrTokenExpired.WithHintf("Authorize code expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, h.trimPrefix(ctx, token, "ac"))
}
