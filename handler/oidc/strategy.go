package oidc

import (
	"net/http"

	"golang.org/x/net/context"
	"github.com/ory-am/fosite"
)

type OpenIDConnectTokenStrategy interface {
	GenerateIDToken(ctx context.Context, r *http.Request, requester fosite.Requester) (token string, err error)
}
