package owner

import (
	"net/http"
	"time"

	"github.com/go-errors/errors"
	"github.com/ory-am/common/pkg"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/handler/core/common"
	"golang.org/x/net/context"
)

type ResourceOwnerPasswordCredentialsGrantHandler struct {
	AccessTokenStrategy core.AccessTokenStrategy

	// Store is used to persist session data across requests.
	Store ResourceOwnerPasswordCredentialsGrantStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration
}

// ValidateTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *ResourceOwnerPasswordCredentialsGrantHandler) ValidateTokenEndpointRequest(_ context.Context, req *http.Request, request fosite.AccessRequester) error {
	// grant_type REQUIRED.
	// Value MUST be set to "password".
	if !request.GetGrantTypes().Exact("password") {
		return nil
	}

	username := req.PostForm.Get("username")
	password := req.PostForm.Get("password")
	if username == "" || password == "" {
		return errors.New(fosite.ErrInvalidRequest)
	} else if err := c.Store.Authenticate(username, password); err == pkg.ErrNotFound {
		return errors.New(fosite.ErrInvalidRequest)
	} else if err != nil {
		return errors.New(fosite.ErrServerError)
	}

	// Credentials must not be passed around, potentially leaking to the database!
	delete(request.GetRequestForm(), "password")

	request.SetGrantTypeHandled("password")
	return nil
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *ResourceOwnerPasswordCredentialsGrantHandler) HandleTokenEndpointRequest(ctx context.Context, req *http.Request, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !requester.GetGrantTypes().Exact("password") {
		return nil
	}

	return common.IssueAccessToken(ctx, c.AccessTokenStrategy, c.Store, c.AccessTokenLifespan, req, requester, responder)
}
