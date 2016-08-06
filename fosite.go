package fosite

import (
	"reflect"

	"github.com/Sirupsen/logrus"
	"github.com/ory-am/fosite/hash"
)

// AuthorizeEndpointHandlers is a list of AuthorizeEndpointHandler
type AuthorizeEndpointHandlers []AuthorizeEndpointHandler

// Add adds an AuthorizeEndpointHandler to this list. Ignores duplicates based on reflect.TypeOf.
func (a *AuthorizeEndpointHandlers) Append(h AuthorizeEndpointHandler) {
	for _, this := range *a {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*a = append(*a, h)
}

// TokenEndpointHandlers is a list of TokenEndpointHandler
type TokenEndpointHandlers []TokenEndpointHandler

// Add adds an TokenEndpointHandler to this list. Ignores duplicates based on reflect.TypeOf.
func (t *TokenEndpointHandlers) Append(h TokenEndpointHandler) {
	for _, this := range *t {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*t = append(*t, h)
}

// TokenValidators is a list of TokenValidator
type TokenValidators []TokenValidator

// Add adds an AccessTokenValidator to this list. Ignores duplicates based on reflect.TypeOf.
func (t *TokenValidators) Append(h TokenValidator) {
	for _, this := range *t {
		if reflect.TypeOf(this) == reflect.TypeOf(h) {
			return
		}
	}

	*t = append(*t, h)
}

// Fosite implements OAuth2Provider.
type Fosite struct {
	Store                     Storage
	AuthorizeEndpointHandlers AuthorizeEndpointHandlers
	TokenEndpointHandlers     TokenEndpointHandlers
	TokenValidators           TokenValidators
	Hasher                    hash.Hasher
	Logger                    logrus.StdLogger
	ScopeStrategy             ScopeStrategy
}
