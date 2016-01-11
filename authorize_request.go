package fosite

import (
	. "github.com/ory-am/fosite/client"
	"net/url"
	"time"
)

// AuthorizeRequester represents an authorize request
type AuthorizeRequester interface {
	// GetResponseTypes returns the requested response types
	GetResponseTypes() Arguments

	// SetResponseTypeHandled marks a response_type (e.g. token or code) as handled indicating that the response type
	// is supported.
	SetResponseTypeHandled(string)

	// DidHandleAllResponseTypes returns if all requested response types have been handled correctly
	DidHandleAllResponseTypes() bool

	// GetClient returns this request's client or nil
	GetClient() Client

	// GetScopes returns this request's scopes
	GetScopes() Arguments

	// GetState returns the request's state
	GetState() string

	// GetRequestedAt returns the time the request was issued
	GetRequestedAt() time.Time

	// GetRedirectURI returns the requested redirect URI
	GetRedirectURI() *url.URL

	// IsRedirectURIValid returns false if the redirect is not rfc-conform (i.e. missing client, not on white list,
	// or malformed)
	IsRedirectURIValid() bool

	// SetScopes sets the request's scopes.
	SetScopes(Arguments)

	// GetGrantScopes returns all granted scopes.
	GetGrantedScopes() Arguments
}

func NewAuthorizeRequest() *AuthorizeRequest {
	return &AuthorizeRequest{
		ResponseTypes:        Arguments{},
		Scopes:               Arguments{},
		HandledResponseTypes: Arguments{},
		GrantedScopes:        []string{},
	}
}

// AuthorizeRequest is an implementation of AuthorizeRequester
type AuthorizeRequest struct {
	ResponseTypes        Arguments
	Client               Client
	Scopes               Arguments
	RedirectURI          *url.URL
	State                string
	RequestedAt          time.Time
	HandledResponseTypes Arguments
	GrantedScopes        []string
}

func (d *AuthorizeRequest) IsRedirectURIValid() bool {
	if d.GetRedirectURI() == nil {
		return false
	}

	raw := d.GetRedirectURI().String()
	if d.GetClient() == nil {
		return false
	}

	redirectURI, err := MatchRedirectURIWithClientRedirectURIs(raw, d.GetClient())
	if err != nil {
		return false
	}
	return IsValidRedirectURI(redirectURI)
}

func (d *AuthorizeRequest) GetResponseTypes() Arguments {
	return d.ResponseTypes
}

func (d *AuthorizeRequest) GetClient() Client {
	return d.Client
}

func (d *AuthorizeRequest) GetScopes() Arguments {
	return d.Scopes
}

func (d *AuthorizeRequest) GetState() string {
	return d.State
}

func (d *AuthorizeRequest) GetRedirectURI() *url.URL {
	return d.RedirectURI
}

func (d *AuthorizeRequest) GetRequestedAt() time.Time {
	return d.RequestedAt
}

func (d *AuthorizeRequest) SetResponseTypeHandled(name string) {
	d.HandledResponseTypes = append(d.HandledResponseTypes, name)
}

func (d *AuthorizeRequest) DidHandleAllResponseTypes() bool {
	for _, rt := range d.ResponseTypes {
		if !d.HandledResponseTypes.Has(rt) {
			return false
		}
	}

	return len(d.ResponseTypes) > 0
}

func (a *AuthorizeRequest) GetGrantedScopes() Arguments {
	return Arguments(a.GrantedScopes)
}

func (a *AuthorizeRequest) GrantScope(scope string) {
	a.GrantedScopes = append(a.GrantedScopes, scope)
}

func (a *AuthorizeRequest) SetScopes(s Arguments) {
	a.Scopes = s
}
