// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"strings"

	"github.com/ory/fosite"
)

var _ CoreStrategy = (*HMACSHAStrategy)(nil)

type HMACSHAStrategy struct {
	*BaseHMACSHAStrategy
}

func (h *HMACSHAStrategy) getPrefix(part string) string {
	return fmt.Sprintf("ory_%s_", part)
}

func (h *HMACSHAStrategy) trimPrefix(token, part string) string {
	return strings.TrimPrefix(token, h.getPrefix(part))
}

func (h *HMACSHAStrategy) setPrefix(token, part string) string {
	if token == "" {
		return ""
	}
	return h.getPrefix(part) + token
}

func (h *HMACSHAStrategy) GenerateAccessToken(ctx context.Context, r fosite.Requester) (token string, signature string, err error) {
	token, sig, err := h.BaseHMACSHAStrategy.GenerateAccessToken(ctx, r)
	return h.setPrefix(token, "at"), sig, err
}

func (h *HMACSHAStrategy) ValidateAccessToken(ctx context.Context, r fosite.Requester, token string) (err error) {
	return h.BaseHMACSHAStrategy.ValidateAccessToken(ctx, r, h.trimPrefix(token, "at"))
}

func (h *HMACSHAStrategy) GenerateRefreshToken(ctx context.Context, r fosite.Requester) (token string, signature string, err error) {
	token, sig, err := h.BaseHMACSHAStrategy.GenerateRefreshToken(ctx, r)
	return h.setPrefix(token, "rt"), sig, err
}

func (h *HMACSHAStrategy) ValidateRefreshToken(ctx context.Context, r fosite.Requester, token string) (err error) {
	return h.BaseHMACSHAStrategy.ValidateRefreshToken(ctx, r, h.trimPrefix(token, "rt"))
}

func (h *HMACSHAStrategy) GenerateAuthorizeCode(ctx context.Context, r fosite.Requester) (token string, signature string, err error) {
	token, sig, err := h.BaseHMACSHAStrategy.GenerateAuthorizeCode(ctx, r)
	return h.setPrefix(token, "ac"), sig, err
}

func (h *HMACSHAStrategy) ValidateAuthorizeCode(ctx context.Context, r fosite.Requester, token string) (err error) {
	return h.BaseHMACSHAStrategy.ValidateAuthorizeCode(ctx, r, h.trimPrefix(token, "ac"))
}
