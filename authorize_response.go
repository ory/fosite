package fosite

import (
	"net/http"
	"net/url"
)

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
