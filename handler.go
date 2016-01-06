package fosite

import (
	"errors"
	"golang.org/x/net/context"
	"net/http"
)

var ErrInvalidResponseType = errors.New("This handler is unable handle any of the response types requested by the auhtorize request")
var ErrNoResponseTypeHandlerFound = errors.New("None of the handler's are able to handle this authorize request")

type ResponseTypeHandler interface {
	// HandleResponseType handles an authorize request. To extend the handler's capabilities, the http request
	// is passed along, if further information retrieval is required.
	//
	// If HandleResponseType fails, the handler implementation MUST return ErrInvalidResponseType.
	HandleResponseType(context.Context, *Response, AuthorizeRequest, http.Request) error
}

// NewAuthorizeResponse iterates through all response type handlers and returns their result or
// ErrNoResponseTypeHandlerFound if none of the handler's were able to handle it.
//
// Important: Every ResponseTypeHandler should return ErrInvalidResponseType if it is unable to handle
// the given request and an arbitrary error if an error occurred
func (o *OAuth2) NewAuthorizeResponse(ctx context.Context, ar *AuthorizeRequest, r *http.Request) (*Response, error) {
	var resp = new(Response)
	var err error
	var found bool

	for _, h := range o.ResponseTypeHandlers {
		// Dereference http request and authorize request so handler's can't mess with it.
		err = h.HandleResponseType(ctx, resp, *ar, *r)
		if err == nil {
			found = true
		} else if err != ErrInvalidResponseType {
			return nil, err
		}
	}

	if !found {
		return nil, ErrNoResponseTypeHandlerFound
	}

	return resp, nil
}
