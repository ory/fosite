// Copyright © 2025 Ory Corp
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
	// ShouldRateLimit checks whether the token request should be rate-limited
	ShouldRateLimit(ctx context.Context, code string) (bool, error)
}

// DeviceCodeStrategy handles the device_code strategy
type DeviceCodeStrategy interface {
	// DeviceCodeSignature calculates the signature of a device_code
	DeviceCodeSignature(ctx context.Context, code string) (signature string, err error)

	// GenerateDeviceCode generates a new device code and signature
	GenerateDeviceCode(ctx context.Context) (code string, signature string, err error)

	// ValidateDeviceCode validates the device_code
	ValidateDeviceCode(ctx context.Context, r fosite.DeviceRequester, code string) (err error)
}

// UserCodeStrategy handles the user_code strategy
type UserCodeStrategy interface {
	// UserCodeSignature calculates the signature of a user_code
	UserCodeSignature(ctx context.Context, code string) (signature string, err error)

	// GenerateUserCode generates a new user code and signature
	GenerateUserCode(ctx context.Context) (code string, signature string, err error)

	// ValidateUserCode validates the user_code
	ValidateUserCode(ctx context.Context, r fosite.DeviceRequester, code string) (err error)
}
