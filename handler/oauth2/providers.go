package oauth2

import "github.com/ory/fosite"

type LifespanConfigProvider interface {
	fosite.AccessTokenLifespanProvider
	fosite.RefreshTokenLifespanProvider
	fosite.AuthorizeCodeLifespanProvider
}
