// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"github.com/ory/fosite"
)

type CoreStrategy interface {
	AccessTokenStrategy
	RefreshTokenStrategy
	AuthorizeCodeStrategy
	DeviceCodeStrategy
	UserCodeStrategy
}

type AccessTokenStrategy interface {
	AccessTokenSignature(ctx context.Context, token string) string
	GenerateAccessToken(ctx context.Context, requester fosite.Requester) (token string, signature string, err error)
	ValidateAccessToken(ctx context.Context, requester fosite.Requester, token string) (err error)
}

type RefreshTokenStrategy interface {
	RefreshTokenSignature(ctx context.Context, token string) string
	GenerateRefreshToken(ctx context.Context, requester fosite.Requester) (token string, signature string, err error)
	ValidateRefreshToken(ctx context.Context, requester fosite.Requester, token string) (err error)
}

type AuthorizeCodeStrategy interface {
	AuthorizeCodeSignature(ctx context.Context, token string) string
	GenerateAuthorizeCode(ctx context.Context, requester fosite.Requester) (token string, signature string, err error)
	ValidateAuthorizeCode(ctx context.Context, requester fosite.Requester, token string) (err error)
}

type DeviceCodeStrategy interface {
	DeviceCodeSignature(ctx context.Context, code string) string
	GenerateDeviceCode(ctx context.Context) (code string, signature string, err error)
	ValidateDeviceCode(ctx context.Context, r fosite.Requester, code string) (err error)
}

type UserCodeStrategy interface {
	UserCodeSignature(ctx context.Context, code string) string
	GenerateUserCode(ctx context.Context) (code string, signature string, err error)
	ValidateUserCode(ctx context.Context, r fosite.Requester, code string) (err error)
}
