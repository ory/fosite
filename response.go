package fosite

import (
	"net/http"
	"net/url"
)

// AuthorizeResponse defines fosite's response model
type AuthorizeResponder interface {
	GetHeader() http.Header
	AddHeader(key, value string)

	GetArguments() url.Values
	AddArgument(key, value string)
}

type AuthorizeResponse struct {
	Header    http.Header
	Arguments url.Values
}

func (a *AuthorizeResponse) GetHeader() http.Header {
	return a.Header
}
func (a *AuthorizeResponse) GetArguments() url.Values {
	return a.Arguments
}
