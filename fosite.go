package fosite

import "github.com/ory-am/fosite/hash"

// AuthorizeEndpointHandlers is a list of AuthorizeEndpointHandler
type AuthorizeEndpointHandlers map[string]AuthorizeEndpointHandler

// Add adds an AuthorizeEndpointHandler to this list
func (a AuthorizeEndpointHandlers) Add(key string, h AuthorizeEndpointHandler) {
	a[key] = h
}

// TokenEndpointHandlers is a list of TokenEndpointHandler
type TokenEndpointHandlers map[string]TokenEndpointHandler

// Add adds an TokenEndpointHandler to this list
func (t TokenEndpointHandlers) Add(key string, h TokenEndpointHandler) {
	t[key] = h
}

// NewFosite returns a new OAuth2Provider implementation
func NewFosite(store Storage) *Fosite {
	return &Fosite{
		Store:                     store,
		RequiredScope:             DefaultRequiredScopeName,
		AuthorizeEndpointHandlers: AuthorizeEndpointHandlers{},
		TokenEndpointHandlers:     TokenEndpointHandlers{},
		Hasher:                    &hash.BCrypt{WorkFactor: 12},
	}
}

// Fosite implements OAuth2Provider.
type Fosite struct {
	RequiredScope             string
	Store                     Storage
	AuthorizeEndpointHandlers AuthorizeEndpointHandlers
	TokenEndpointHandlers     TokenEndpointHandlers
	Hasher                    hash.Hasher
}
