package client

import "github.com/ory-am/fosite/handler/core"

type ClientCredentialsGrantStorage interface {
	core.AccessTokenStorage
}
