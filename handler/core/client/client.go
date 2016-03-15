package client

import (
	"net/http"
	"time"

	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/handler/core/common"
	"golang.org/x/net/context"
)

type ClientCredentialsGrantHandler struct {
	// AccessTokenStrategy is the algorithm responsible for creating a validatable token.
	AccessTokenStrategy core.AccessTokenStrategy

	// Store is used to persist session data across requests.
	Store ClientCredentialsGrantStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration
}

// ValidateTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.4.2
func (c *ClientCredentialsGrantHandler) HandleTokenEndpointRequest(_ context.Context, r *http.Request, request fosite.AccessRequester) error {
	// grant_type REQUIRED.
	// Value MUST be set to "client_credentials".
	if !request.GetGrantTypes().Exact("client_credentials") {
		return nil
	}

	// The client MUST authenticate with the authorization server as described in Section 3.2.1.
	// This requirement is already fulfilled because fosite requries all token requests to be authenticated as described
	// in https://tools.ietf.org/html/rfc6749#section-3.2.1

	// There's nothing else to do. All other security considerations are for the client side.
	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.4.3
func (c *ClientCredentialsGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, r *http.Request, request fosite.AccessRequester, response fosite.AccessResponder) error {
	if !request.GetGrantTypes().Exact("client_credentials") {
		return nil
	}

	return common.IssueAccessToken(ctx, c.AccessTokenStrategy, c.Store, c.AccessTokenLifespan, r, request, response)
}
