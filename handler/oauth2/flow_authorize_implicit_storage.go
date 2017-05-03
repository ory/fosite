package oauth2

import (
	"context"

	"github.com/ory/fosite"
)

type ImplicitGrantStorage interface {
	CreateImplicitAccessTokenSession(ctx context.Context, token string, request fosite.Requester) (err error)
}
