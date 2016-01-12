package refresh

import "github.com/ory-am/fosite/handler/core"

type RefreshTokenGrantStorage interface {
	core.AccessTokenStorage
	core.RefreshTokenStorage
}
