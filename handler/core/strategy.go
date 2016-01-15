package core

import (
	"github.com/ory-am/fosite/client"
	"golang.org/x/net/context"
	"net/http"
)

type Request interface {
	GetClient() client.Client
	GetContext() context.Context
	GetRequest() *http.Request
}

type AccessTokenStrategy interface {
	GenerateAccessToken(ctx context.Context, req *http.Request, requester Request) (token string, signature string, err error)
	ValidateAccessToken(token string, ctx context.Context, req *http.Request, requester Request) (signature string, err error)
}

type RefreshTokenStrategy interface {
	GenerateRefreshToken(ctx context.Context, req *http.Request, requester Request) (token string, signature string, err error)
	ValidateRefreshToken(token string, ctx context.Context, req *http.Request, requester Request) (signature string, err error)
}

type AuthorizeCodeStrategy interface {
	GenerateAuthorizeCode(ctx context.Context, req *http.Request, requester Request) (token string, signature string, err error)
	ValidateAuthorizeCode(token string, ctx context.Context, req *http.Request, requester Request) (signature string, err error)
}
