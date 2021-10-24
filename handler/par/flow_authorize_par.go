package par

import (
	"context"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

// AuthorizePARHandler implements the handler that consumes the PAR request_uri
type AuthorizePARHandler struct {
	Storage          PARStorage
	RequestURIPrefix string
}

// HandleAuthorizeEndpointRequest handles the authorize endpoint request for PAR
func (c *AuthorizePARHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, _ fosite.AuthorizeResponder) error {
	requestURI := ar.GetRequestForm().Get("request_uri")
	if requestURI == "" || !strings.HasPrefix(requestURI, c.RequestURIPrefix) {
		// nothing to do here
		return nil
	}

	// hydrate the requester
	if err := c.Storage.GetPARSession(ctx, requestURI, ar); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidRequestURI.WithHint("Invalid PAR session").WithWrap(err).WithDebug(err.Error()))
	}

	if err := c.Storage.DeletePARSession(ctx, requestURI); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// validate the clients match
	if ar.GetRequestForm().Get("client_id") != ar.GetClient().GetID() {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("'client_id' must match the pushed authorization request"))
	}

	return nil
}
