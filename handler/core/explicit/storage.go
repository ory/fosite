package explicit

import (
	"github.com/ory-am/fosite/handler/core"
)

type AuthorizeCodeGrantStorage interface {
	core.AuthorizeCodeStorage
	core.AccessTokenStorage
	core.RefreshTokenStorage
}
