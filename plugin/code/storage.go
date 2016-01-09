package code

import "github.com/ory-am/fosite"

type CodeResponseTypeStorage interface {
	CreateAuthorizeCodeSession(code string, authorizeRequest fosite.AuthorizeRequester, extra interface{}) error

	GetAuthorizeCodeSession(code string, authorizeRequest fosite.AuthorizeRequester, extra interface{}) error

	DeleteAuthorizeCodeSession(code string) error
}
