package fosite

import (
	"github.com/ory-am/fosite/client"
	"time"
)

type AccessRequester interface {
	// GetGrantType returns the requests grant type.
	GetGrantType() string

	// GetClient returns the requests client.
	GetClient() client.Client

	// GetRequestedAt returns the time the request was created.
	GetRequestedAt() time.Time

	// GetScopes returns the request's scopes.
	GetScopes() Arguments

	// SetScopes sets the request's scopes.
	SetScopes(Arguments)

	// GetGrantScopes returns all granted scopes.
	GetGrantedScopes() Arguments

	// GrantScope marks a request's scope as granted.
	GrantScope(string)

	// SetGrantTypeHandled marks a grant type as handled indicating that the response type is supported.
	SetGrantTypeHandled(string)

	// DidHandleGrantType returns if the requested grant type has been handled correctly.
	DidHandleGrantType() bool
}

type AccessRequest struct {
	GrantType        string
	HandledGrantType []string
	RequestedAt      time.Time
	Client           client.Client
	Scopes           Arguments
	GrantedScopes    []string
}

func NewAccessRequest() *AccessRequest {
	return &AccessRequest{
		RequestedAt:      time.Now(),
		HandledGrantType: []string{},
	}
}

func (a *AccessRequest) DidHandleGrantType() bool {
	return StringInSlice(a.GrantType, a.HandledGrantType)
}

func (a *AccessRequest) SetGrantTypeHandled(name string) {
	a.HandledGrantType = append(a.HandledGrantType, name)
}

func (a *AccessRequest) GetGrantType() string {
	return a.GrantType
}

func (a *AccessRequest) GetRequestedAt() time.Time {
	return a.RequestedAt
}

func (a *AccessRequest) GetClient() client.Client {
	return a.Client
}

func (a *AccessRequest) GetScopes() Arguments {
	return a.Scopes
}

func (a *AccessRequest) SetScopes(s Arguments) {
	a.Scopes = s
}

func (a *AccessRequest) GetGrantedScopes() Arguments {
	return Arguments(a.GrantedScopes)
}

func (a *AccessRequest) GrantScope(scope string) {
	a.GrantedScopes = append(a.GrantedScopes, scope)
}
