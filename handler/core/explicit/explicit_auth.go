package explicit

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"golang.org/x/net/context"
)

const authCodeDefaultLifespan = time.Hour / 2

// CodeAuthorizeEndpointHandler is a response handler for the Authorize Code grant using the explicit grant type
// as defined in https://tools.ietf.org/html/rfc6749#section-4.1
type AuthorizeExplicitGrantTypeHandler struct {
	AccessTokenStrategy   core.AccessTokenStrategy
	RefreshTokenStrategy  core.RefreshTokenStrategy
	AuthorizeCodeStrategy core.AuthorizeCodeStrategy

	// Store is used to persist session data across requests.
	Store AuthorizeCodeGrantStorage

	// AuthCodeLifespan defines the lifetime of an authorize code.
	AuthCodeLifespan time.Duration

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration
}

func (c *AuthorizeExplicitGrantTypeHandler) HandleAuthorizeEndpointRequest(ctx context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) error {
	// This let's us define multiple response types, for example open id connect's id_token
	if ar.GetResponseTypes().Has("code") {
		// Generate the code
		code, signature, err := c.AuthorizeCodeStrategy.GenerateAuthorizeCode(ctx, req, ar)
		if err != nil {
			return errors.New(ErrServerError)
		}

		if err := c.Store.CreateAuthorizeCodeSession(signature, ar); err != nil {
			return errors.New(ErrServerError)
		}

		resp.AddQuery("code", code)
		resp.AddQuery("state", ar.GetState())
		resp.AddQuery("scope", strings.Join(ar.GetGrantedScopes(), " "))
		ar.SetResponseTypeHandled("code")
		return nil
	}

	return nil
}
