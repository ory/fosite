package implicit

import (
	"github.com/ory-am/fosite"
)

type ImplicitGrantStorage interface {
	CreateImplicitAccessTokenSession(string, fosite.AuthorizeRequester) error
}
