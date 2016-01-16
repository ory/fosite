package client

import (
	"github.com/go-errors/errors"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"golang.org/x/net/context"
	"net/http"
	"strconv"
	"strings"
	"time"
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
func (c *ClientCredentialsGrantHandler) ValidateTokenEndpointRequest(_ context.Context, r *http.Request, request fosite.AccessRequester) error {
	// grant_type REQUIRED.
	// Value MUST be set to "client_credentials".
	if request.GetGrantType() != "client_credentials" {
		return nil
	}

	// The client MUST authenticate with the authorization server as described in Section 3.2.1.
	// This requirement is already fulfilled because fosite requries all token requests to be authenticated as described
	// in https://tools.ietf.org/html/rfc6749#section-3.2.1

	// There's nothing else to do. All other security considerations are for the client side.

	request.SetGrantTypeHandled("client_credentials")
	return nil
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.4.3
func (c *ClientCredentialsGrantHandler) HandleTokenEndpointRequest(ctx context.Context, r *http.Request, request fosite.AccessRequester, response fosite.AccessResponder) error {
	if request.GetGrantType() != "client_credentials" {
		return nil
	}

	token, signature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, r, request)
	if err != nil {
		return errors.New(fosite.ErrServerError)
	} else if err := c.Store.CreateAccessTokenSession(signature, request); err != nil {
		return errors.New(fosite.ErrServerError)
	}

	response.SetAccessToken(token)
	response.SetTokenType("bearer")
	response.SetExtra("expires_in", strconv.Itoa(int(c.AccessTokenLifespan/time.Second)))
	response.SetExtra("scope", strings.Join(request.GetGrantedScopes(), " "))

	// "A refresh token SHOULD NOT be included."
	// -> we won't issue one

	return nil
}
