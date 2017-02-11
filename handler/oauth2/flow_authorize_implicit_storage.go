package oauth2

import (
	"github.com/ory/fosite"
	"golang.org/x/net/context"
)

type ImplicitGrantStorage interface {
	CreateImplicitAccessTokenSession(ctx context.Context, token string, request fosite.Requester) (err error)
}
