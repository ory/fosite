package core

import (
	"net/http"

	"github.com/ory-am/fosite"
	"golang.org/x/net/context"
)

type AccessTokenStrategy interface {
	GenerateAccessToken(ctx context.Context, req *http.Request, requester fosite.Requester) (token string, signature string, err error)
	ValidateAccessToken(ctx context.Context, token string, req *http.Request, requester fosite.Requester) (signature string, err error)
}

type RefreshTokenStrategy interface {
	GenerateRefreshToken(ctx context.Context, req *http.Request, requester fosite.Requester) (token string, signature string, err error)
	ValidateRefreshToken(ctx context.Context, token string, req *http.Request, requester fosite.Requester) (signature string, err error)
}

type AuthorizeCodeStrategy interface {
	GenerateAuthorizeCode(ctx context.Context, req *http.Request, requester fosite.Requester) (token string, signature string, err error)
	ValidateAuthorizeCode(ctx context.Context, token string, req *http.Request, requester fosite.Requester) (signature string, err error)
}
