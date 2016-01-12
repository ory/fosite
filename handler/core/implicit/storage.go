package implicit

import (
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
)

type ImplicitGrantStorage interface {
	CreateImplicitAccessTokenSession(string, fosite.AuthorizeRequester, *core.AuthorizeSession) error
}
