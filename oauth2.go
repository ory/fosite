package fosite

import (
	"golang.org/x/net/context"
	"net/http"
)

// OAuth2Provider
type OAuth2Provider interface {
	// NewAuthorizeRequest returns an AuthorizeRequest. This method makes rfc6749 compliant
	// checks:
	// * rfc6749 3.1.   Authorization Endpoint
	// * rfc6749 3.1.1. Response Type
	// * rfc6749 3.1.2. Redirection Endpoint
	// * rfx6749 10.6.  Authorization Code Redirection URI Manipulation
	//
	// It also introduces countermeasures described in rfc6819:
	// * rfc6819 4.4.1.7.  Threat: Authorization "code" Leakage through Counterfeit Client
	// * rfc6819 4.4.1.8.  Threat: CSRF Attack against redirect-uri
	NewAuthorizeRequest(context.Context, *http.Request) (AuthorizeRequester, error)

	// NewAuthorizeResponse iterates through all response type handlers and returns their result or
	// ErrNoResponseTypeHandlerFound if none of the handler's were able to handle it.
	//
	// Important: Every ResponseTypeHandler should return ErrInvalidResponseType if it is unable to handle
	// the given request and an arbitrary error if an error occurred
	NewAuthorizeResponse(ctx context.Context, req *http.Request, ar AuthorizeRequest, session interface{}) (AuthorizeResponder, error)

	// WriteAuthorizeError returns the error codes to the redirection endpoint or shows the error to the user, if no valid
	// redirect uri was given. Implements rfc6749#section-4.1.2.1
	WriteAuthorizeError(http.ResponseWriter, AuthorizeRequester, error)

	// WriteAuthorizeResponse persists the AuthorizeSession in the store and redirects the user agent to the provided
	// redirect url or returns an error if storage failed.
	WriteAuthorizeResponse(http.ResponseWriter, AuthorizeRequester, AuthorizeResponder)
}

// Fosite ships all the various oauth2 helpers like NewAuthorizeRequest
type Fosite struct {
	Store                Storage
	ResponseTypeHandlers []ResponseTypeHandler
}
