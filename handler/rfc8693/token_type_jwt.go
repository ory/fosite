// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"time"

	"github.com/ory/fosite/token/jwt"
)

type JWTType struct {
	Name                string `json:"name"`
	Issuer              string `json:"iss"`
	JWTValidationConfig `json:"validate"`
	JWTIssueConfig      `json:"issue"`
}

type JWTIssueConfig struct {
	Audience []string      `json:"aud"`
	Expiry   time.Duration `json:"exp"`
}

type JWTValidationConfig struct {
	ValidateJTI                bool          `json:"validate_jti"`
	JWTLifetimeToleranceWindow time.Duration `json:"tolerance_window"`
	ValidateFunc               jwt.Keyfunc   `json:"-"`
}

func (c *JWTType) GetName(ctx context.Context) string {
	return c.Name
}

func (c *JWTType) GetType(ctx context.Context) string {
	return JWTTokenType
}
