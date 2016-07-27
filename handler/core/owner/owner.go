package owner

import (
	"net/http"

	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"github.com/pkg/errors"
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
		return errors.Wrap(fosite.ErrUnknownRequest, "")
	}

	if !request.GetClient().GetGrantTypes().Has("password") {
		return errors.Wrap(fosite.ErrInvalidGrant, "")
	}

	username, password, ok := req.BasicAuth()
	if !ok {
		username = req.PostForm.Get("username")
		password = req.PostForm.Get("password")
	}

	if username == "" || password == "" {
		return errors.Wrap(fosite.ErrInvalidRequest, "")
	} else if err := c.ResourceOwnerPasswordCredentialsGrantStorage.Authenticate(ctx, username, password); errors.Cause(err) == fosite.ErrNotFound {
		return errors.Wrap(fosite.ErrInvalidRequest, err.Error())
	} else if err != nil {
		return errors.Wrap(fosite.ErrServerError, err.Error())
	}

	// Credentials must not be passed around, potentially leaking to the database!
	delete(request.GetRequestForm(), "password")
	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *ResourceOwnerPasswordCredentialsGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, req *http.Request, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !requester.GetGrantTypes().Exact("password") {
		return errors.Wrap(fosite.ErrUnknownRequest, "")
	}

	return c.IssueAccessToken(ctx, req, requester, responder)
}
