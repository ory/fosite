package oauth2

import (
	"context"

	"github.com/ory/fosite"
)

type AuthorizeCodeGrantStorage interface {
	AuthorizeCodeStorage

	PersistAuthorizeCodeGrantSession(ctx context.Context, authorizeCode, accessSignature, refreshSignature string, request fosite.Requester) error
}
