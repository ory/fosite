package implicit

import (
	"github.com/ory-am/fosite"
)

type ImplicitGrantStorage interface {
	CreateImplicitAccessTokenSession(token string, request fosite.Requester) (err error)
}
