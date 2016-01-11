package explicit

import (
	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/enigma"
	. "github.com/ory-am/fosite/handler/authorize"
	"golang.org/x/net/context"
	"net/http"
	"time"
)

const authCodeDefaultLifespan = time.Hour / 2

// CodeAuthorizeEndpointHandler is a response handler for the Authorize Code grant using the explicit grant type
// as defined in https://tools.ietf.org/html/rfc6749#section-4.1
type AuthorizeExplicitEndpointHandler struct {
	// Enigma is the algorithm responsible for creating a validatable, opaque string.
	Enigma enigma.Enigma

	// Store is used to persist session data across requests.
	Store AuthorizeStorage

	// AuthCodeLifespan defines the lifetime of an authorize code.
	AuthCodeLifespan time.Duration

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration
}

func (c *AuthorizeExplicitEndpointHandler) HandleAuthorizeEndpointRequest(_ context.Context, resp AuthorizeResponder, ar AuthorizeRequester, req *http.Request, session interface{}) error {
	// This let's us define multiple response types, for example open id connect's id_token
	if ar.GetResponseTypes().Has("code") {
		// Generate the code
		code, err := c.Enigma.GenerateChallenge(ar.GetClient().GetHashedSecret())
		if err != nil {
			return errors.Wrap(err, 1)
		}

		if err := c.Store.CreateAuthorizeCodeSession(code.Signature, ar, &AuthorizeSession{
			Extra:              session,
			RequestRedirectURI: req.Form.Get("redirect_uri"),
		}); err != nil {
			return errors.Wrap(err, 1)
		}

		resp.AddQuery("code", code.String())
		ar.SetResponseTypeHandled("code")
		return nil
	}

	return nil
}
