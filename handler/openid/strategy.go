// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

type OpenIDConnectTokenStrategy interface {
	GenerateIDToken(ctx context.Context, lifespan time.Duration, requester fosite.Requester) (token string, err error)
}

type OpenIDConnectTokenValidationStrategy interface {
	ValidateIDToken(ctx context.Context, requester fosite.Requester, token string) (jwt.MapClaims, error)
}
