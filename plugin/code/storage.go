package code

import "github.com/ory-am/fosite"

type CodeResponseTypeStorage interface {
	StoreAuthorizeCodeSession(code string, authorizeRequest fosite.AuthorizeRequester, extra interface{}) error
}
