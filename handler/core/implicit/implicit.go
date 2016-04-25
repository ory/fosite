package implicit

import (
	"net/http"
	"time"

	"strconv"
	"strings"

	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"golang.org/x/net/context"
)

// AuthorizeImplicitGrantTypeHandler is a response handler for the Authorize Code grant using the implicit grant type
// as defined in https://tools.ietf.org/html/rfc6749#section-4.2
type AuthorizeImplicitGrantTypeHandler struct {
	AccessTokenStrategy core.AccessTokenStrategy

	// ImplicitGrantStorage is used to persist session data across requests.
	AccessTokenStorage core.AccessTokenStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration
}

func (c *AuthorizeImplicitGrantTypeHandler) HandleAuthorizeEndpointRequest(ctx context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) error {
	// This let's us define multiple response types, for example open id connect's id_token
	if !ar.GetResponseTypes().Exact("token") {
		return nil
	}

	return c.IssueImplicitAccessToken(ctx, req, ar, resp)
}

func (c *AuthorizeImplicitGrantTypeHandler) IssueImplicitAccessToken(ctx context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) error {
	// Generate the code
	token, signature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, ar)
	if err != nil {
		return errors.New(ErrServerError)
	} else if err := c.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, ar); err != nil {
		return errors.New(ErrServerError)
	}

	resp.AddFragment("access_token", token)
	resp.AddFragment("expires_in", strconv.Itoa(int(c.AccessTokenLifespan/time.Second)))
	resp.AddFragment("token_type", "bearer")
	resp.AddFragment("state", ar.GetState())
	resp.AddFragment("scope", strings.Join(ar.GetGrantedScopes(), "+"))
	ar.SetResponseTypeHandled("token")

	return nil
}
