package oauth2

import (
	"strings"
	"time"

	"fmt"

	"context"
	"strconv"

	"github.com/ory/fosite"
	"github.com/pkg/errors"
)

// AuthorizeImplicitGrantTypeHandler is a response handler for the Authorize Code grant using the implicit grant type
// as defined in https://tools.ietf.org/html/rfc6749#section-4.2
type AuthorizeImplicitGrantTypeHandler struct {
	AccessTokenStrategy AccessTokenStrategy

	// AccessTokenStorage is used to persist session data across requests.
	AccessTokenStorage AccessTokenStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration

	ScopeStrategy fosite.ScopeStrategy
}

func (c *AuthorizeImplicitGrantTypeHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	// This let's us define multiple response types, for example open id connect's id_token
	if !ar.GetResponseTypes().Exact("token") {
		return nil
	}

	if !ar.GetClient().GetResponseTypes().Has("token") {
		return errors.Wrap(fosite.ErrInvalidGrant, "The client is not allowed to use response type token")
	}

	if !ar.GetClient().GetGrantTypes().Has("implicit") {
		return errors.Wrap(fosite.ErrInvalidGrant, "The client is not allowed to use grant type implicit")
	}

	client := ar.GetClient()
	for _, scope := range ar.GetRequestedScopes() {
		if !c.ScopeStrategy(client.GetScopes(), scope) {
			return errors.Wrap(fosite.ErrInvalidScope, fmt.Sprintf("The client is not allowed to request scope %s", scope))
		}
	}

	// there is no need to check for https, because implicit flow does not require https
	// https://tools.ietf.org/html/rfc6819#section-4.4.2

	return c.IssueImplicitAccessToken(ctx, ar, resp)
}

func (c *AuthorizeImplicitGrantTypeHandler) IssueImplicitAccessToken(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	// Generate the code
	token, signature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, ar)
	if err != nil {
		return errors.Wrap(fosite.ErrServerError, err.Error())
	}

	ar.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().Add(c.AccessTokenLifespan))
	if err := c.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, ar); err != nil {
		return errors.Wrap(fosite.ErrServerError, err.Error())
	}

	resp.AddFragment("access_token", token)
	resp.AddFragment("expires_in", strconv.FormatInt(int64(getExpiresIn(ar, fosite.AccessToken, c.AccessTokenLifespan, time.Now())/time.Second), 10))
	resp.AddFragment("token_type", "bearer")
	resp.AddFragment("state", ar.GetState())
	resp.AddFragment("scope", strings.Join(ar.GetGrantedScopes(), " "))
	ar.SetResponseTypeHandled("token")

	return nil
}
