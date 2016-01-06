package fosite

import (
	"net/http"
	"net/url"
)

// AuthorizeResponse defines fosite's response model
type AuthorizeResponse struct {
	Header http.Header
	Query  url.Values
}
