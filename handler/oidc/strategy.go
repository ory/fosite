package oidc

import (
	"net/http"

	"github.com/ory-am/fosite"
	"golang.org/x/net/context"
)

type OpenIDConnectTokenStrategy interface {
	GenerateIDToken(ctx context.Context, r *http.Request, requester fosite.Requester, claims map[string]interface{}) (token string, err error)
}
