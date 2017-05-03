package openid

import (
	"net/http"

	"context"

	"github.com/ory/fosite"
)

type OpenIDConnectTokenStrategy interface {
	GenerateIDToken(ctx context.Context, r *http.Request, requester fosite.Requester) (token string, err error)
}
