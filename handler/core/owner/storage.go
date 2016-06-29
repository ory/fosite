package owner

import (
	"github.com/ory-am/fosite/handler/core"
	"golang.org/x/net/context"
)

type ResourceOwnerPasswordCredentialsGrantStorage interface {
	core.AccessTokenStorage

	Authenticate(
		ctx context.Context,
		name string,
		secret string,
	) (context.Context, error)
}
