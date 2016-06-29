package implicit

import (
	"github.com/ory-am/fosite"
	"golang.org/x/net/context"
)

type ImplicitGrantStorage interface {
	CreateImplicitAccessTokenSession(
		ctx context.Context,
		token string,
		request fosite.Requester,
	) (context.Context, error)
}
