package oidc

import (
	"net/http"

	"github.com/ory-am/fosite/handler/oidc/strategy"
	"golang.org/x/net/context"
)

type OpenIDConnectTokenStrategy interface {
	GenerateIDToken(ctx context.Context, req *http.Request, session strategy.IDTokenSession) (token string, err error)
}
