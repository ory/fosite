package oauth2

import (
	"github.com/ory/fosite"
	"context"
)

type RefreshTokenGrantStorage interface {
	RefreshTokenStorage
	PersistRefreshTokenGrantSession(ctx context.Context, requestRefreshSignature, accessSignature, refreshSignature string, request fosite.Requester) error
}
