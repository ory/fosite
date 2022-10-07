// Copyright © 2022 Ory Corp

package oauth2

import (
	"context"
)

type ResourceOwnerPasswordCredentialsGrantStorage interface {
	Authenticate(ctx context.Context, name string, secret string) error
	AccessTokenStorage
	RefreshTokenStorage
}
