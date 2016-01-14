package core

import (
	"github.com/ory-am/fosite"
	"golang.org/x/net/context"
	"net/http"
)

type AccessTokenStrategy interface {
	GenerateAccessToken(ctx context.Context, req *http.Request, requester fosite.AccessRequester, session interface{}) (token string, signature string, err error)
	ValidateAccessToken(token string) (signature string, err error)
}

type RefreshTokenStrategy interface {
	GenerateRefreshToken(ctx context.Context, req *http.Request, requester fosite.AccessRequester, session interface{}) (token string, signature string, err error)
	ValidateRefreshToken(token string) (signature string, err error)
}

type AuthorizeCodeStrategy interface {
	GenerateAuthorizeCode(ctx context.Context, req *http.Request, requester fosite.AuthorizeRequester, session interface{}) (token string, signature string, err error)
	ValidateAuthorizeCode(token string, ctx context.Context, req *http.Request, requester fosite.AuthorizeRequester, session interface{}) (signature string, err error)
}
