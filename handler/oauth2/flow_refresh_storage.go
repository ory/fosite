package oauth2

import (
	"github.com/ory/fosite"
	"golang.org/x/net/context"
)

type RefreshTokenGrantStorage interface {
	RefreshTokenStorage
	PersistRefreshTokenGrantSession(ctx context.Context, requestRefreshSignature, accessSignature, refreshSignature string, request fosite.Requester) error
}
