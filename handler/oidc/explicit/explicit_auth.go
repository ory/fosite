package explicit

import (
	"net/http"

	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	. "github.com/ory-am/fosite/handler/oidc"
	"github.com/ory-am/fosite/handler/oidc/strategy"
	"golang.org/x/net/context"
)

type OpenIDConnectExplicitHandler struct {
	// OpenIDConnectRequestStorage is the storage for open id connect sessions.
	OpenIDConnectRequestStorage OpenIDConnectRequestStorage

	// OpenIDConnectTokenStrategy is the strategy for generating id tokens.
	OpenIDConnectTokenStrategy OpenIDConnectTokenStrategy
}

func (c *OpenIDConnectExplicitHandler) HandleAuthorizeEndpointRequest(ctx context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) error {
	if !(ar.GetScopes().Has("openid") && ar.GetResponseTypes().Exact("code")) {
		return nil
	}

	session, ok := ar.GetSession().(*strategy.IDTokenSession)
	if !ok {
		return errors.New(ErrServerError)
	}

	// OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
	// Although optional, this is considered good practice and therefore enforced.
	if ar.GetRequestForm().Get("nonce") == "" {
		return errors.New(ErrInvalidRequest)
	}

	session.JWTClaims.AddExtra("nonce") = ar.GetRequestForm().Get("nonce")
	if err := c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(resp.GetID()); err != nil {
		return errors.New(ErrServerError)
	}

	return nil
}
