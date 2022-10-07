// Copyright © 2022 Ory Corp

package openid

import (
	"context"
	"time"

	"github.com/ory/fosite"
)

type OpenIDConnectTokenStrategy interface {
	GenerateIDToken(ctx context.Context, lifespan time.Duration, requester fosite.Requester) (token string, err error)
}
