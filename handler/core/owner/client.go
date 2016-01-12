package owner

import (
	"github.com/go-errors/errors"
	"github.com/ory-am/common/pkg"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/enigma"
	"github.com/ory-am/fosite/handler/core"
	"golang.org/x/net/context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ResourceOwnerPasswordCredentialsGrantHandler struct {
	// Enigma is the algorithm responsible for creating a validatable, opaque string.
	Enigma enigma.Enigma

	// Store is used to persist session data across requests.
	Store ResourceOwnerPasswordCredentialsGrantStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration
}

// ValidateTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *ResourceOwnerPasswordCredentialsGrantHandler) ValidateTokenEndpointRequest(_ context.Context, req *http.Request, request fosite.AccessRequester, session interface{}) error {
	// grant_type REQUIRED.
	// Value MUST be set to "password".
	if request.GetGrantType() != "password" {
		return nil
	}

	username := req.PostForm.Get("username")
	password := req.PostForm.Get("password")
	if username == "" || password == "" {
		return errors.New(fosite.ErrInvalidRequest)
	} else if err := c.Store.DoCredentialsAuthenticate(username, password); err == pkg.ErrNotFound {
		return errors.New(fosite.ErrInvalidRequest)
	} else if err != nil {
		return errors.New(fosite.ErrServerError)
	}

	request.SetGrantTypeHandled("password")
	return nil
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *ResourceOwnerPasswordCredentialsGrantHandler) HandleTokenEndpointRequest(ctx context.Context, req *http.Request, requester fosite.AccessRequester, responder fosite.AccessResponder, session interface{}) error {
	if requester.GetGrantType() != "password" {
		return nil
	}

	access, err := c.Enigma.GenerateChallenge(requester.GetClient().GetHashedSecret())
	if err != nil {
		return errors.New(fosite.ErrServerError)
	} else if err := c.Store.CreateAccessTokenSession(access.Signature, requester, &core.TokenSession{}); err != nil {
		return errors.New(fosite.ErrServerError)
	}

	responder.SetAccessToken(access.String())
	responder.SetTokenType("bearer")
	responder.SetExtra("expires_in", strconv.Itoa(int(c.AccessTokenLifespan/time.Second)))
	responder.SetExtra("scope", strings.Join(requester.GetGrantedScopes(), " "))

	// As of https://tools.ietf.org/html/rfc6819#section-5.2.2.1 and
	// https://tools.ietf.org/html/rfc6819#section-4.4.3.3 we decided not to include refresh tokens
	// as part of the resource owner grant

	return nil
}
