package refresh

import (
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"golang.org/x/net/context"
)

type RefreshTokenGrantStorage interface {
	core.RefreshTokenStorage

	PersistRefreshTokenGrantSession(
		ctx context.Context,
		requestRefreshSignature, accessSignature, refreshSignature string,
		request fosite.Requester,
	) (context.Context, error)
}
