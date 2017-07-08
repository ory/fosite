package oauth2

import (
	"context"

	"github.com/ory/fosite"
)

type RefreshTokenGrantStorage interface {
	RefreshTokenStorage

	// PersistRefreshTokenGrantSession persists a refresh token grant session. It should delete
	// old access and refresh tokens, and then persist the new access and refresh signatures.
	PersistRefreshTokenGrantSession(ctx context.Context, requestRefreshSignature, accessSignature, refreshSignature string, request fosite.Requester) error
}
