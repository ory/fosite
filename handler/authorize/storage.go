package authorize

import (
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/token"
)

type AuthorizeSession struct {
	RequestRedirectURI string
	Extra              interface{}
}

type AuthorizeStorage interface {
	CreateAuthorizeCodeSession(string, fosite.AuthorizeRequester, *AuthorizeSession) error

	GetAuthorizeCodeSession(string, *AuthorizeSession) (fosite.AuthorizeRequester, error)

	DeleteAuthorizeCodeSession(code string) error

	token.TokenStorage
}
