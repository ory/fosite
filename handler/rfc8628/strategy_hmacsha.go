// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"crypto/rand"
	"math/big"
	"strings"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
	enigma "github.com/ory/fosite/token/hmac"
)

type DefaultDeviceStrategy struct {
	Enigma *enigma.HMACStrategy
	Config interface {
		fosite.DeviceAndUserCodeLifespanProvider
	}
}

func (h *DefaultDeviceStrategy) generateRandomString(length int) (token string, err error) {
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

func (h *DefaultDeviceStrategy) GenerateUserCode(ctx context.Context) (token string, signature string, err error) {
	userCode, err := h.generateRandomString(8)
	if err != nil {
		return "", "", err
	}
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
