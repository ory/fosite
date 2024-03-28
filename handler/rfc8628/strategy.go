// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"

	"github.com/ory/fosite"
)

// RFC8628CodeStrategy is the code strategy needed for the DeviceAuthHandler
type RFC8628CodeStrategy interface {
	DeviceRateLimitStrategy
	DeviceCodeStrategy
	UserCodeStrategy
}

// DeviceRateLimitStrategy handles the rate limiting strategy
type DeviceRateLimitStrategy interface {
	ShouldRateLimit(ctx context.Context, code string) (bool, error)
}

// DeviceCodeStrategy handles the device_code strategy
type DeviceCodeStrategy interface {
	DeviceCodeSignature(ctx context.Context, code string) (signature string, err error)
	GenerateDeviceCode(ctx context.Context) (code string, signature string, err error)
	ValidateDeviceCode(ctx context.Context, r fosite.Requester, code string) (err error)
}

// UserCodeStrategy handles the user_code strategy
type UserCodeStrategy interface {
	UserCodeSignature(ctx context.Context, code string) (signature string, err error)
	GenerateUserCode(ctx context.Context) (code string, signature string, err error)
	ValidateUserCode(ctx context.Context, r fosite.Requester, code string) (err error)
}
