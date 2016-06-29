package fosite

import (
	"net/url"
	"time"
)

// Request is an implementation of Requester
type Request struct {
	RequestedAt   time.Time   `json:"requestedAt" gorethink:"requestedAt"`
	Client        Client      `json:"client" gorethink:"client"`
	Scopes        Arguments   `json:"scopes" gorethink:"scopes"`
	GrantedScopes Arguments   `json:"grantedScopes" gorethink:"grantedScopes"`
	Form          url.Values  `json:"form" gorethink:"form"`
	Session       interface{} `json:"session" gorethink:"session"`
}

func NewRequest() *Request {
	return &Request{
		Client:      &DefaultClient{},
		Scopes:      Arguments{},
		GrantedScopes:      Arguments{},
		Form:        url.Values{},
		RequestedAt: time.Now(),
	}
}

func (a *Request) GetRequestForm() url.Values {
	return a.Form
}

func (a *Request) GetRequestedAt() time.Time {
	return a.RequestedAt
}

func (a *Request) GetClient() Client {
	return a.Client
}

func (a *Request) GetScopes() Arguments {
	return Unique(a.Scopes)
}

func (a *Request) SetScopes(s Arguments) {
	a.Scopes = s
}

func (a *Request) GetGrantedScopes() Arguments {
	return Unique(a.GrantedScopes)
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

func (a *Request) Merge(request Requester) {
	for _, scope := range request.GetScopes() {
		a.Scopes = append(a.Scopes, scope)
	}
	for _, scope := range request.GetGrantedScopes() {
		a.GrantedScopes = append(a.GrantedScopes, scope)
	}
	a.RequestedAt = request.GetRequestedAt()
	a.Client = request.GetClient()
	a.Session = request.GetSession()

	for k, v := range request.GetRequestForm() {
		a.Form[k] = v
	}
}

func Unique(col []string) Arguments {
	m := map[string]struct{}{}
	for _, v := range col {
		if _, ok := m[v]; !ok {
			m[v] = struct{}{}
		}
	}
	list := make([]string, len(m))

	i := 0
	for v := range m {
		list[i] = v
		i++
	}
	return Arguments(list)
}
