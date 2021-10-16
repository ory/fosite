package par

import (
	"context"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

type AuthorizePARHandler struct {
	Storage          PARStorage
	RequestURIPrefix string
}

func (c *AuthorizePARHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, _ fosite.AuthorizeResponder) error {
	requestURI := ar.GetRequestForm().Get("request_uri")
	if requestURI == "" || !strings.HasPrefix(requestURI, c.RequestURIPrefix) {
		// nothing to do here
		return nil
	}

	// hydrate the requester
	err := c.Storage.GetPARSession(ctx, requestURI, ar)
	if err != nil {
		return errorsx.WithStack(fosite.ErrInvalidRequestURI.WithHint("Invalid PAR session").WithWrap(err).WithDebug(err.Error()))
	}

	c.Storage.DeletePARSession(ctx, requestURI)

	// validate the clients match
	if ar.GetRequestForm().Get("client_id") != ar.GetClient().GetID() {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("'client_id' must match the pushed authorization request"))
	}

	return nil
}
