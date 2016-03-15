package fosite

import (
	"net/url"
	"time"

	"github.com/ory-am/fosite/client"
)

// Request is an implementation of Requester
type Request struct {
	RequestedAt   time.Time
	Client        client.Client
	Scopes        Arguments
	GrantedScopes Arguments
	Form          url.Values
	Session       interface{}
}

func NewRequest() *Request {
	return &Request{
		Client: &client.SecureClient{},
		Scopes: Arguments{},
		Form:   url.Values{},
	}
}

func (a *Request) GetRequestForm() url.Values {
	return a.Form
}

func (a *Request) GetRequestedAt() time.Time {
	return a.RequestedAt
}

func (a *Request) GetClient() client.Client {
	return a.Client
}

func (a *Request) GetScopes() Arguments {
	return a.Scopes
}

func (a *Request) SetScopes(s Arguments) {
	a.Scopes = s
}

func (a *Request) GetGrantedScopes() Arguments {
	return a.GrantedScopes
}

func (a *Request) GrantScope(scope string) {
	a.GrantedScopes = append(a.GrantedScopes, scope)
}

func (a *Request) SetSession(session interface{}) {
	a.Session = session
}

func (a *Request) GetSession() interface{} {
	return a.Session
}
