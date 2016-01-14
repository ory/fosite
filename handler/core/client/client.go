package client

import (
	"github.com/go-errors/errors"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/enigma"
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
func (c *ClientCredentialsGrantHandler) ValidateTokenEndpointRequest(_ context.Context, req *http.Request, request fosite.AccessRequester, session interface{}) error {
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
func (c *ClientCredentialsGrantHandler) HandleTokenEndpointRequest(ctx context.Context, req *http.Request, requester fosite.AccessRequester, responder fosite.AccessResponder, session interface{}) error {
	if requester.GetGrantType() != "client_credentials" {
		return nil
	}

	token, signature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, req, requester, session)
	if err != nil {
		return errors.New(fosite.ErrServerError)
	} else if err := c.Store.CreateAccessTokenSession(signature, requester, &core.TokenSession{}); err != nil {
		return errors.New(fosite.ErrServerError)
	}

	responder.SetAccessToken(token)
	responder.SetTokenType("bearer")
	responder.SetExtra("expires_in", strconv.Itoa(int(c.AccessTokenLifespan/time.Second)))
	responder.SetExtra("scope", strings.Join(requester.GetGrantedScopes(), " "))

	// "A refresh token SHOULD NOT be included."
	// -> we won't issue one

	return nil
}
