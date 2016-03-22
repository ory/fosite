package fosite

import "github.com/ory-am/fosite/hash"

// AuthorizeEndpointHandlers is a list of AuthorizeEndpointHandler
type AuthorizeEndpointHandlers []AuthorizeEndpointHandler

// Add adds an AuthorizeEndpointHandler to this list
func (a *AuthorizeEndpointHandlers) Append(h AuthorizeEndpointHandler) {
	*a = append(*a, h)
}

// TokenEndpointHandlers is a list of TokenEndpointHandler
type TokenEndpointHandlers []TokenEndpointHandler

// Add adds an TokenEndpointHandler to this list
func (t *TokenEndpointHandlers) Append(h TokenEndpointHandler) {
	*t = append(*t, h)
}

// AuthorizedRequestValidators is a list of AuthorizedRequestValidator
type AuthorizedRequestValidators []AuthorizedRequestValidator

// Add adds an AccessTokenValidator to this list
func (t *AuthorizedRequestValidators) Append(h AuthorizedRequestValidator) {
	*t = append(*t, h)
}

// NewFosite returns a new OAuth2Provider implementation
func NewFosite(store Storage) *Fosite {
	return &Fosite{
		Store:                       store,
		MandatoryScope:              DefaultMandatoryScope,
		AuthorizeEndpointHandlers:   AuthorizeEndpointHandlers{},
		TokenEndpointHandlers:       TokenEndpointHandlers{},
		AuthorizedRequestValidators: AuthorizedRequestValidators{},
		Hasher: &hash.BCrypt{WorkFactor: 12},
	}
}

// Fosite implements OAuth2Provider.
type Fosite struct {
	MandatoryScope              string
	Store                       Storage
	AuthorizeEndpointHandlers   AuthorizeEndpointHandlers
	TokenEndpointHandlers       TokenEndpointHandlers
	AuthorizedRequestValidators AuthorizedRequestValidators
	Hasher                      hash.Hasher
}
