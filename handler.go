package fosite

import (
	"errors"
	"golang.org/x/net/context"
	"net/http"
	"net/url"
)

// ErrInvalidResponseType is thrown by a ResponseTypeHandler if it is not responsible for handling the authorize request.
var ErrInvalidResponseType = errors.New("This handler is unable handle any of the response types requested by the auhtorize request")

// ErrNoResponseTypeHandlerFound is thrown if no ResponseTypeHandler was found responsible for the request.
var ErrNoResponseTypeHandlerFound = errors.New("None of the handler's are able to handle this authorize request")

type ResponseTypeHandler interface {
	// HandleResponseType handles an authorize request. To extend the handler's capabilities, the http request
	// is passed along, if further information retrieval is required.
	//
	// If HandleResponseType fails, the handler implementation MUST return ErrInvalidResponseType.
	HandleResponseType(context.Context, *AuthorizeResponder, AuthorizeRequester, http.Request, session interface{}) error
}
