package refresh

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

type RefreshTokenGrantHandler struct {
	// Enigma is the algorithm responsible for creating a validatable, opaque string.
	Enigma enigma.Enigma

	// Store is used to persist session data across requests.
	Store RefreshTokenGrantStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration
}

// ValidateTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) ValidateTokenEndpointRequest(_ context.Context, req *http.Request, request fosite.AccessRequester, session interface{}) error {
	// grant_type REQUIRED.
	// Value MUST be set to "client_credentials".
	if request.GetGrantType() != "refresh_token" {
		return nil
	}

	// The authorization server MUST ... validate the refresh token.
	challenge := new(enigma.Challenge)
	challenge.FromString(req.Form.Get("refresh_token"))
	if err := c.Enigma.ValidateChallenge(request.GetClient().GetHashedSecret(), challenge); err != nil {
		return fosite.ErrInvalidRequest
	}

	var ts core.TokenSession
	ar, err := c.Store.GetRefreshTokenSession(challenge.Signature, &ts)
	if err == pkg.ErrNotFound {
		return fosite.ErrInvalidRequest
	} else if err != nil {
		return fosite.ErrServerError
	}

	// The authorization server MUST ... and ensure that the refresh token was issued to the authenticated client
	if ar.GetClient().GetID() != request.GetClient().GetID() {
		return fosite.ErrInvalidRequest
	}

	request.SetGrantTypeHandled("refresh_token")
	return nil
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) HandleTokenEndpointRequest(ctx context.Context, req *http.Request, requester fosite.AccessRequester, responder fosite.AccessResponder, session interface{}) error {
	if requester.GetGrantType() != "refresh_token" {
		return nil
	}

	access, err := c.Enigma.GenerateChallenge(requester.GetClient().GetHashedSecret())
	if err != nil {
		return errors.New(fosite.ErrServerError)
	} else if err := c.Store.CreateAccessTokenSession(access.Signature, requester, &core.TokenSession{}); err != nil {
		return errors.New(fosite.ErrServerError)
	}

	refresh, err := c.Enigma.GenerateChallenge(requester.GetClient().GetHashedSecret())
	if err != nil {
		return errors.New(fosite.ErrServerError)
	} else if err := c.Store.CreateRefreshTokenSession(refresh.Signature, requester, &core.TokenSession{}); err != nil {
		return errors.New(fosite.ErrServerError)
	}

	challenge := new(enigma.Challenge)
	challenge.FromString(req.Form.Get("refresh_token"))
	if err := c.Store.DeleteRefreshTokenSession(challenge.Signature); err != nil {
		return errors.New(fosite.ErrServerError)
	}

	responder.SetAccessToken(access.String())
	responder.SetTokenType("bearer")
	responder.SetExtra("expires_in", strconv.Itoa(int(c.AccessTokenLifespan/time.Second)))
	responder.SetExtra("scope", strings.Join(requester.GetGrantedScopes(), " "))
	responder.SetExtra("refresh_token", refresh.String())
	return nil
}
