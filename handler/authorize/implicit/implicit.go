package implicit

import (
	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/enigma"
	"github.com/ory-am/fosite/handler/authorize"
	"golang.org/x/net/context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// CodeAuthorizeEndpointHandler is a response handler for the Authorize Code grant using the explicit grant type
// as defined in https://tools.ietf.org/html/rfc6749#section-4.1
type AuthorizeImplicitEndpointHandler struct {
	// Enigma is the algorithm responsible for creating a validatable, opaque string.
	Enigma enigma.Enigma

	// Store is used to persist session data across requests.
	Store authorize.AuthorizeImplicitStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration
}

func (c *AuthorizeImplicitEndpointHandler) HandleAuthorizeEndpointRequest(_ context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder, session interface{}) error {
	// This let's us define multiple response types, for example open id connect's id_token
	if ar.GetResponseTypes().Has("token") {
		// Generate the code
		access, err := c.Enigma.GenerateChallenge(ar.GetClient().GetHashedSecret())
		if err != nil {
			return errors.New(ErrServerError)
		}

		if err := c.Store.CreateImplicitAccessTokenSession(access.Signature, ar, &authorize.AuthorizeSession{
			Extra:              session,
			RequestRedirectURI: req.Form.Get("redirect_uri"),
		}); err != nil {
			return errors.New(ErrServerError)
		}

		resp.AddFragment("access_token", access.String())
		resp.AddFragment("expires_in", strconv.Itoa(int(c.AccessTokenLifespan/time.Second)))
		resp.AddFragment("token_type", "bearer")
		resp.AddFragment("state", ar.GetState())
		resp.AddFragment("scope", strings.Join(ar.GetGrantedScopes(), "+"))
		ar.SetResponseTypeHandled("token")
		return nil
	}

	return nil
}
