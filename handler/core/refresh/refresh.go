package refresh

import (
	"github.com/go-errors/errors"
	"github.com/ory-am/common/pkg"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"golang.org/x/net/context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type RefreshTokenGrantHandler struct {
	AccessTokenStrategy core.AccessTokenStrategy

	RefreshTokenStrategy core.RefreshTokenStrategy

	// Store is used to persist session data across requests.
	Store RefreshTokenGrantStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration
}

// ValidateTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) ValidateTokenEndpointRequest(ctx context.Context, req *http.Request, request fosite.AccessRequester) error {
	// grant_type REQUIRED.
	// Value MUST be set to "client_credentials".
	if request.GetGrantType() != "refresh_token" {
		return nil
	}

	// The authorization server MUST ... validate the refresh token.
	signature, err := c.RefreshTokenStrategy.ValidateRefreshToken(req.Form.Get("refresh_token"), ctx, req, request)
	if err != nil {
		return errors.New(fosite.ErrInvalidRequest)
	}

	ar, err := c.Store.GetRefreshTokenSession(signature)
	if err == pkg.ErrNotFound {
		return errors.New(fosite.ErrInvalidRequest)
	} else if err != nil {
		return errors.New(fosite.ErrServerError)
	}

	// The authorization server MUST ... and ensure that the refresh token was issued to the authenticated client
	if ar.GetClient().GetID() != request.GetClient().GetID() {
		return errors.New(fosite.ErrInvalidRequest)
	}

	request.SetGrantTypeHandled("refresh_token")
	return nil
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) HandleTokenEndpointRequest(ctx context.Context, req *http.Request, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if requester.GetGrantType() != "refresh_token" {
		return nil
	}

	accessToken, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, req, requester)
	if err != nil {
		return errors.New(fosite.ErrServerError)
	} else if err := c.Store.CreateAccessTokenSession(accessSignature, requester); err != nil {
		return errors.New(fosite.ErrServerError)
	}

	refreshToken, refreshSignature, err := c.RefreshTokenStrategy.GenerateRefreshToken(ctx, req, requester)
	if err != nil {
		return errors.New(fosite.ErrServerError)
	} else if err := c.Store.CreateRefreshTokenSession(refreshSignature, requester); err != nil {
		return errors.New(fosite.ErrServerError)
	}

	if err := c.Store.DeleteRefreshTokenSession(req.Form.Get("refresh_token")); err != nil {
		return errors.New(fosite.ErrServerError)
	}

	responder.SetAccessToken(accessToken)
	responder.SetTokenType("bearer")
	responder.SetExtra("expires_in", strconv.Itoa(int(c.AccessTokenLifespan/time.Second)))
	responder.SetExtra("scope", strings.Join(requester.GetGrantedScopes(), " "))
	responder.SetExtra("refresh_token", refreshToken)
	return nil
}
