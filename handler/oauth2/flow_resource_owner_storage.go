// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
)

type ResourceOwnerPasswordCredentialsGrantStorage interface {
	Authenticate(ctx context.Context, name string, secret string) (subject string, err error)
	AccessTokenStorage
	RefreshTokenStorage
}
