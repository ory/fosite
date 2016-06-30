package refresh

import (
	"net/http"
	"time"

	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

type RefreshTokenGrantHandler struct {
	AccessTokenStrategy core.AccessTokenStrategy

	RefreshTokenStrategy core.RefreshTokenStrategy

	// RefreshTokenGrantStorage is used to persist session data across requests.
	RefreshTokenGrantStorage RefreshTokenGrantStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) HandleTokenEndpointRequest(ctx context.Context, req *http.Request, request fosite.AccessRequester) (context.Context, error) {
	// grant_type REQUIRED.
	// Value MUST be set to "client_credentials".
	if !request.GetGrantTypes().Exact("refresh_token") {
		return ctx, errors.Wrap(fosite.ErrUnknownRequest, "")
	}

	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return ctx, errors.Wrap(fosite.ErrInvalidGrant, "")
	}

	refresh := req.PostForm.Get("refresh_token")
	signature := c.RefreshTokenStrategy.RefreshTokenSignature(refresh)
	ctx, accessRequest, err := c.RefreshTokenGrantStorage.GetRefreshTokenSession(ctx, signature, nil)
	if errors.Cause(err) == fosite.ErrNotFound {
		return ctx, errors.Wrap(fosite.ErrInvalidRequest, err.Error())
	} else if err != nil {
		return ctx, errors.Wrap(fosite.ErrServerError, err.Error())
	}

	// The authorization server MUST ... validate the refresh token.
	if err := c.RefreshTokenStrategy.ValidateRefreshToken(ctx, request, refresh); err != nil {
		return ctx, errors.Wrap(fosite.ErrInvalidRequest, err.Error())
	}

	request.SetScopes(accessRequest.GetScopes())
	for _, scope := range accessRequest.GetGrantedScopes() {
		request.GrantScope(scope)
	}

	// The authorization server MUST ... and ensure that the refresh token was issued to the authenticated client
	if accessRequest.GetClient().GetID() != request.GetClient().GetID() {
		return ctx, errors.Wrap(fosite.ErrInvalidRequest, "")
	}
	return ctx, nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, req *http.Request, requester fosite.AccessRequester, responder fosite.AccessResponder) (context.Context, error) {
	if !requester.GetGrantTypes().Exact("refresh_token") {
		return ctx, errors.Wrap(fosite.ErrUnknownRequest, "")
	}

	accessToken, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return ctx, errors.Wrap(fosite.ErrServerError, err.Error())
	}

	refreshToken, refreshSignature, err := c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
	if err != nil {
		return ctx, errors.Wrap(fosite.ErrServerError, err.Error())
	}

	signature := c.RefreshTokenStrategy.RefreshTokenSignature(req.PostForm.Get("refresh_token"))
	if ctx, err = c.RefreshTokenGrantStorage.PersistRefreshTokenGrantSession(ctx, signature, accessSignature, refreshSignature, requester); err != nil {
		return ctx, errors.Wrap(fosite.ErrServerError, err.Error())
	}

	responder.SetAccessToken(accessToken)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(c.AccessTokenLifespan / time.Second)
	responder.SetScopes(requester.GetGrantedScopes())
	responder.SetExtra("refresh_token", refreshToken)
	return ctx, nil
}
