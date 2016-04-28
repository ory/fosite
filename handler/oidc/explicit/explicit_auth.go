package explicit

import (
	"net/http"

	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	. "github.com/ory-am/fosite/handler/oidc"
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

	if len(resp.GetCode()) == 0 {
		return errors.New(ErrMisconfiguration)
	}

	if err := c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, resp.GetCode(), ar); err != nil {
		return errors.New(ErrServerError)
	}

	return nil
}
