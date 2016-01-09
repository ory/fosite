package fosite

import (
	"net/http"
	"net/url"
)

import (
	"golang.org/x/net/context"
)

func (c *Fosite) WriteAuthorizeResponse(rw http.ResponseWriter, ar AuthorizeRequester, resp AuthorizeResponder) {
	redir := ar.GetRedirectURI()

	// Explicit grants
	q := redir.Query()
	rq := resp.GetQuery()
	for k, _ := range rq {
		q.Set(k, rq.Get(k))
	}
	redir.RawQuery = q.Encode()

	// Set custom headers, e.g. "X-MySuperCoolCustomHeader" or "X-DONT-CACHE-ME"...
	wh := rw.Header()
	rh := resp.GetHeader()
	for k, _ := range rh {
		wh.Set(k, rh.Get(k))
	}

	// Implicit grants
	redir.Fragment = resp.GetFragment().Encode()

	// https://tools.ietf.org/html/rfc6749#section-4.1.1
	// When a decision is established, the authorization server directs the
	// user-agent to the provided client redirection URI using an HTTP
	// redirection response, or by other means available to it via the
	// user-agent.
	wh.Set("Location", redir.String())
	rw.WriteHeader(http.StatusFound)
}

func (o *Fosite) NewAuthorizeResponse(ctx context.Context, r *http.Request, ar AuthorizeRequester, session interface{}) (AuthorizeResponder, error) {
	var resp = NewAuthorizeResponse()
	var err error
	var found int

	for _, h := range o.AuthorizeEndpointHandlers {
		err = h.HandleAuthorizeEndpointRequest(ctx, resp, ar, r, session)
		if err == nil {
			found++
		} else if err != ErrHandlerNotResponsible {
			return nil, err
		}
	}

	if found != len(ar.GetResponseTypes()) {
		return nil, ErrUnsupportedResponseType
	}

	return resp, nil
}

// AuthorizeResponder defines fosite's response model
type AuthorizeResponder interface {
	GetHeader() http.Header
	AddHeader(key, value string)

	GetQuery() url.Values
	AddQuery(key, value string)

	GetFragment() url.Values
	AddFragment(key, value string)
}

// NewAuthorizeResponse creates a new AuthorizeResponse
func NewAuthorizeResponse() *AuthorizeResponse {
	return &AuthorizeResponse{
		Header:   &http.Header{},
		Query:    &url.Values{},
		Fragment: &url.Values{},
	}
}

// AuthorizeResponse is an implementation of AuthorizeResponder
type AuthorizeResponse struct {
	Header   *http.Header
	Query    *url.Values
	Fragment *url.Values
}

func (a *AuthorizeResponse) GetHeader() http.Header {
	return *a.Header
}

func (a *AuthorizeResponse) AddHeader(key, value string) {
	a.Header.Add(key, value)
}

func (a *AuthorizeResponse) GetQuery() url.Values {
	return *a.Query
}

func (a *AuthorizeResponse) GetFragment() url.Values {
	return *a.Fragment
}

func (a *AuthorizeResponse) AddQuery(key, value string) {
	a.Query.Add(key, value)
}

func (a *AuthorizeResponse) AddFragment(key, value string) {
	a.Fragment.Add(key, value)
}
