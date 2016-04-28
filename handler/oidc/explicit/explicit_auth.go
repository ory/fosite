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

	*IDTokenHandleHelper
}

func (c *OpenIDConnectExplicitHandler) HandleAuthorizeEndpointRequest(ctx context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) error {
	if !(ar.GetScopes().Has("openid") && ar.GetResponseTypes().Exact("code")) {
		return nil
	}

	session, ok := ar.GetSession().(strategy.IDTokenContainer)
	if !ok {
		return errors.New(ErrServerError)
	}

	nonce := ar.GetRequestForm().Get("nonce")
	// OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
	// Although optional, this is considered good practice and therefore enforced.
	if len(nonce) < MinParameterEntropy {
		// We're assuming that using less then 8 characters for the state can not be considered "unguessable"
		return errors.New(ErrInsufficientEntropy)
	}

	if len(resp.GetCode()) < 1 {
		return errors.New(ErrMisconfiguration)
	}

	session.GetIDTokenClaims().Add("nonce", nonce)
	if err := c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, resp.GetCode(), ar); err != nil {
		return errors.New(ErrServerError)
	}

	return nil
}
