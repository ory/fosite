package oauth2

import (
	"net/http"

	"fmt"

	"github.com/ory-am/fosite"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

type ClientCredentialsGrantHandler struct {
	*HandleHelper
	ScopeStrategy fosite.ScopeStrategy
}

// ValidateTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.4.2
func (c *ClientCredentialsGrantHandler) HandleTokenEndpointRequest(_ context.Context, r *http.Request, request fosite.AccessRequester) error {
	// grant_type REQUIRED.
	// Value MUST be set to "client_credentials".
	if !request.GetGrantTypes().Exact("client_credentials") {
		return errors.Wrap(fosite.ErrUnknownRequest, "")
	}

	client := request.GetClient()
	for _, scope := range request.GetRequestedScopes() {
		if !c.ScopeStrategy(client.GetScopes(), scope) {
			return errors.Wrap(fosite.ErrInvalidScope, fmt.Sprintf("The client is not allowed to request scope %s", scope))
		}
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
		return errors.Wrap(fosite.ErrUnknownRequest, "")
	}

	if !request.GetClient().GetGrantTypes().Has("client_credentials") {
		return errors.Wrap(fosite.ErrInvalidGrant, "The client is not allowed to use grant type client_credentials")
	}

	return c.IssueAccessToken(ctx, r, request, response)
}
