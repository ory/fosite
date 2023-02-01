// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"strings"
	"time"

	"github.com/ory/x/errorsx"
	"github.com/ory/x/randx"

	"github.com/ory/fosite"
	enigma "github.com/ory/fosite/token/hmac"
)

type DefaultDeviceStrategy struct {
	RFC8628CodeStrategy

	Enigma *enigma.HMACStrategy
	Config interface {
		fosite.DeviceAndUserCodeLifespanProvider
	}
}

func (h *DefaultDeviceStrategy) GenerateUserCode(ctx context.Context) (token string, signature string, err error) {
	seq, err := randx.RuneSequence(8, []rune("BCDFGHJKLMNPQRSTVWXZ"))
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

func (h *DefaultDeviceStrategy) UserCodeSignature(ctx context.Context, token string) (signature string, err error) {
	return h.Enigma.GenerateHMACForString(ctx, token)
}

func (h *DefaultDeviceStrategy) ValidateUserCode(ctx context.Context, r fosite.Requester, code string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.UserCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrDeviceExpiredToken.WithHintf("User code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx))))
	}
	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrDeviceExpiredToken.WithHintf("User code expired at '%s'.", exp))
	}
	return nil
}

func (h *DefaultDeviceStrategy) GenerateDeviceCode(ctx context.Context) (token string, signature string, err error) {
	token, sig, err := h.Enigma.Generate(ctx)
	if err != nil {
		return "", "", err
	}

	return "ory_dc_" + token, sig, nil
}

func (h *DefaultDeviceStrategy) DeviceCodeSignature(ctx context.Context, token string) (signature string, err error) {
	return h.Enigma.Signature(token), nil
}

func (h *DefaultDeviceStrategy) ValidateDeviceCode(ctx context.Context, r fosite.Requester, code string) (err error) {
	var exp = r.GetSession().GetExpiresAt(fosite.DeviceCode)
	if exp.IsZero() && r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx)).Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrDeviceExpiredToken.WithHintf("Device code expired at '%s'.", r.GetRequestedAt().Add(h.Config.GetDeviceAndUserCodeLifespan(ctx))))
	}

	if !exp.IsZero() && exp.Before(time.Now().UTC()) {
		return errorsx.WithStack(fosite.ErrDeviceExpiredToken.WithHintf("Device code expired at '%s'.", exp))
	}

	return h.Enigma.Validate(ctx, strings.TrimPrefix(code, "ory_dc_"))
}
