package owner

import (
	"net/http"

	"github.com/go-errors/errors"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"golang.org/x/net/context"
)

type ResourceOwnerPasswordCredentialsGrantHandler struct {
	// ResourceOwnerPasswordCredentialsGrantStorage is used to persist session data across requests.
	ResourceOwnerPasswordCredentialsGrantStorage ResourceOwnerPasswordCredentialsGrantStorage

	*core.HandleHelper
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *ResourceOwnerPasswordCredentialsGrantHandler) HandleTokenEndpointRequest(ctx context.Context, req *http.Request, request fosite.AccessRequester) error {
	// grant_type REQUIRED.
	// Value MUST be set to "password".
	if !request.GetGrantTypes().Exact("password") {
		return errors.New(fosite.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("password") {
		return errors.New(fosite.ErrInvalidGrant)
	}

	username := req.PostForm.Get("username")
	password := req.PostForm.Get("password")
	if username == "" || password == "" {
		return errors.New(fosite.ErrInvalidRequest)
	} else if err := c.ResourceOwnerPasswordCredentialsGrantStorage.Authenticate(ctx, username, password); errors.Is(err, fosite.ErrNotFound) {
		return errors.New(fosite.ErrInvalidRequest)
	} else if err != nil {
		return errors.New(fosite.ErrServerError)
	}

	// Credentials must not be passed around, potentially leaking to the database!
	delete(request.GetRequestForm(), "password")
	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *ResourceOwnerPasswordCredentialsGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, req *http.Request, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !requester.GetGrantTypes().Exact("password") {
		return errors.New(fosite.ErrUnknownRequest)
	}

	return c.IssueAccessToken(ctx, req, requester, responder)
}
