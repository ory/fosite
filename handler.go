package fosite

import (
	"net/http"

	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

var ErrUnknownRequest = errors.New("The handler is not responsible for this request.")

type AuthorizeEndpointHandler interface {
	// HandleAuthorizeRequest handles an authorize endpoint request. To extend the handler's capabilities, the http request
	// is passed along, if further information retrieval is required. If the handler feels that he is not responsible for
	// the authorize request, he must return nil and NOT modify session nor responder neither requester.
	//
	// The following spec is a good example of what HandleAuthorizeRequest should do.
	// * https://tools.ietf.org/html/rfc6749#section-3.1.1
	//   response_type REQUIRED.
	//   The value MUST be one of "code" for requesting an
	//   authorization code as described by Section 4.1.1, "token" for
	//   requesting an access token (implicit grant) as described by
	//   Section 4.2.1, or a registered extension value as described by Section 8.4.
	HandleAuthorizeEndpointRequest(ctx context.Context, req *http.Request, requester AuthorizeRequester, responder AuthorizeResponder) error
}

type TokenEndpointHandler interface {
	// PopulateTokenEndpointResponse is responsible for setting return values and should only be executed if
	// the handler's HandleTokenEndpointRequest did not return ErrUnknownRequest.
	PopulateTokenEndpointResponse(ctx context.Context, req *http.Request, requester AccessRequester, responder AccessResponder) error

	// HandleTokenEndpointRequest handles an authorize request. If the handler is not responsible for handling
	// the request, this method should return ErrUnknownRequest and otherwise handle the request.
	HandleTokenEndpointRequest(ctx context.Context, req *http.Request, requester AccessRequester) error
}
