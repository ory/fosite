package fosite

import (
	"github.com/ory-am/fosite/client"
	"net/url"
	"time"
)

// Request is an implementation of Requester
type Request struct {
	RequestedAt   time.Time
	Client        client.Client
	Scopes        Arguments
	GrantedScopes []string
	Form          url.Values
	Session       interface{}
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
	return Arguments(a.GrantedScopes)
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
