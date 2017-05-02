package oauth2

import (
	"github.com/ory-am/fosite"
	"context"
)

type ImplicitGrantStorage interface {
	CreateImplicitAccessTokenSession(ctx context.Context, token string, request fosite.Requester) (err error)
}
