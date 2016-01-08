package fosite

import (
	"errors"
	"golang.org/x/net/context"
	"net/http"
)

// ErrInvalidResponseType is thrown by a ResponseTypeHandler if it is not responsible for handling the authorize request.
var ErrInvalidResponseType = errors.New("This handler is unable handle any of the response types requested by the auhtorize request")

// ErrNoResponseTypeHandlerFound is thrown if no ResponseTypeHandler was found responsible for the request.
var ErrNoResponseTypeHandlerFound = errors.New("None of the handler's are able to handle this authorize request")

type ResponseTypeHandler interface {
	// HandleResponseType handles an authorize request. To extend the handler's capabilities, the http request
	// is passed along, if further information retrieval is required. If HandleResponseType fails, the handler
	// implementation MUST return ErrInvalidResponseType.
	//
	// HandleResponseType should implement:
	// * https://tools.ietf.org/html/rfc6749#section-3.1.1
	//   response_type REQUIRED.
	//   The value MUST be one of "code" for requesting an
	//   authorization code as described by Section 4.1.1, "token" for
	//   requesting an access token (implicit grant) as described by
	//   Section 4.2.1, or a registered extension value as described by Section 8.4.
	//
	// HandleResponseType could also implement additional things like open id connect spec.
	HandleResponseType(ctx context.Context, responder AuthorizeResponder, requester AuthorizeRequester, req *http.Request, session interface{}) error
}
