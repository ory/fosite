package openid

import (
	"net/http"

	"github.com/ory-am/fosite"
	"context"
)

type OpenIDConnectTokenStrategy interface {
	GenerateIDToken(ctx context.Context, r *http.Request, requester fosite.Requester) (token string, err error)
}
