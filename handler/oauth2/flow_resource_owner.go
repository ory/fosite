package oauth2

import (
	"net/http"

	"fmt"

	"github.com/ory-am/fosite"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

type ResourceOwnerPasswordCredentialsGrantHandler struct {
	// ResourceOwnerPasswordCredentialsGrantStorage is used to persist session data across requests.
	ResourceOwnerPasswordCredentialsGrantStorage ResourceOwnerPasswordCredentialsGrantStorage

	ScopeStrategy fosite.ScopeStrategy

	*HandleHelper
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *ResourceOwnerPasswordCredentialsGrantHandler) HandleTokenEndpointRequest(ctx context.Context, req *http.Request, request fosite.AccessRequester) error {
	// grant_type REQUIRED.
	// Value MUST be set to "password".
	if !request.GetGrantTypes().Exact("password") {
		return errors.Wrap(fosite.ErrUnknownRequest, "")
	}

	if !request.GetClient().GetGrantTypes().Has("password") {
		return errors.Wrap(fosite.ErrInvalidGrant, "The client is not allowed to use grant type password")
	}

	username := req.PostForm.Get("username")
	password := req.PostForm.Get("password")
	if username == "" || password == "" {
		return errors.Wrap(fosite.ErrInvalidRequest, "Username or password missing")
	} else if err := c.ResourceOwnerPasswordCredentialsGrantStorage.Authenticate(ctx, username, password); errors.Cause(err) == fosite.ErrNotFound {
		return errors.Wrap(fosite.ErrInvalidRequest, err.Error())
	} else if err != nil {
		return errors.Wrap(fosite.ErrServerError, err.Error())
	}

	client := request.GetClient()
	for _, scope := range request.GetRequestedScopes() {
		if !c.ScopeStrategy(client.GetScopes(), scope) {
			return errors.Wrap(fosite.ErrInvalidScope, fmt.Sprintf("The client is not allowed to request scope %s", scope))
		}
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
