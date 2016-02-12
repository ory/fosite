package owner

import "github.com/ory-am/fosite/handler/core"

type ResourceOwnerPasswordCredentialsGrantStorage interface {
	Authenticate(name string, secret string) error
	core.AccessTokenStorage
}
