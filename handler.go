package fosite

import (
	"errors"
	"golang.org/x/net/context"
	"net/http"
)

// ErrUnaccountableForAuthorizeRequest is thrown by a AuthorizeEndpointHandler if it is not responsible for handling the authorize request.
var ErrHandlerNotResponsible = errors.New("This handler is not feeling responsible for handling this request")

// ErrNoAuthorizeEndpointHandlerFound is thrown if no AuthorizeEndpointHandler was found responsible for the request.
var ErrNoAuthorizeEndpointHandlerFound = errors.New("None of the handler's are able to handle this authorize request")

type AuthorizeEndpointHandler interface {
	// HandleAuthorizeRequest handles an authorize endpoint request. To extend the handler's capabilities, the http request
	// is passed along, if further information retrieval is required. If HandleAuthorizeRequest fails, the handler
	// implementation MUST return ErrHandlerNotResponsible.
	//
	// The following spec is a good example of what HandleAuthorizeRequest should do.
	// * https://tools.ietf.org/html/rfc6749#section-3.1.1
	//   response_type REQUIRED.
	//   The value MUST be one of "code" for requesting an
	//   authorization code as described by Section 4.1.1, "token" for
	//   requesting an access token (implicit grant) as described by
	//   Section 4.2.1, or a registered extension value as described by Section 8.4.
	HandleAuthorizeEndpointRequest(ctx context.Context, responder AuthorizeResponder, requester AuthorizeRequester, req *http.Request, session interface{}) error
}

type TokenEndpointSessionLoader interface {
	// HandleAuthorizeRequest handles an authorize endpoint request.
	LoadTokenEndpointSession(ctx context.Context, request AccessRequester, req *http.Request, session interface{}) error
}

type TokenEndpointHandler interface {
	// HandleAuthorizeRequest handles an authorize request. To extend the handler's capabilities, the http request
	// is passed along, if further information retrieval is required. If HandleAuthorizeRequest fails, the handler
	// implementation MUST return ErrInvalidResponseType.
	//
	HandleTokenEndpointRequest(ctx context.Context, responder AccessResponder, requester AccessRequester, req *http.Request, session interface{}) error
}
