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
	GetRedirectURI() *url.URL
	GetState() string
	GetRequestedAt() time.Time
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

func (d *AuthorizeRequest) GetResponseTypes() Arguments {
	return d.ResponseTypes
}

func (d *AuthorizeRequest) GetClient() Client {
	return d.Client
}

func (d *AuthorizeRequest) GetScopes() Arguments {
	return d.Scopes
}

func (d *AuthorizeRequest) GetState() Arguments {
	return d.State
}

func (d *AuthorizeRequest) GetRedirectURI() *url.URL {
	return d.RedirectURI
}

func (d *AuthorizeRequest) GetRequestedAt() time.Time {
	return d.RequestedAt
}
