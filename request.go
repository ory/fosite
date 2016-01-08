package fosite

import (
	. "github.com/ory-am/fosite/client"
	"net/url"
	"time"
)

type AuthorizeRequester interface {
	GetResponseTypes() Arguments
	GetClient() Client
	GetScopes() Arguments
	GetState() string
	GetRequestedAt() time.Time

	GetRedirectURI() *url.URL
	IsRedirectURIValid() bool
}

// Authorize request information
type AuthorizeRequest struct {
	ResponseTypes Arguments
	Client        Client
	Scopes        Arguments
	RedirectURI   *url.URL
	State         string
	RequestedAt   time.Time
}

func (d *AuthorizeRequest) IsRedirectURIValid() bool {
	// Validate redirect uri
	raw := d.GetRedirectURI().String()
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
