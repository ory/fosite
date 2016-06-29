package explicit

import (
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"golang.org/x/net/context"
)

type AuthorizeCodeGrantStorage interface {
	core.AuthorizeCodeStorage

	PersistAuthorizeCodeGrantSession(
		ctx context.Context,
		authorizeCode, accessSignature, refreshSignature string,
		request fosite.Requester,
	) (context.Context, error)
}
