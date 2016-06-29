package explicit

import (
	"net/http"

	. "github.com/ory-am/fosite"
	. "github.com/ory-am/fosite/handler/oidc"
	"github.com/pkg/errors"
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

	if !ar.GetClient().GetResponseTypes().Has("id_token", "code") {
		return errors.Wrap(ErrInvalidClient, "client is not allowed to use rseponse type id_token and code")
	}

	if len(resp.GetCode()) == 0 {
		return errors.Wrap(ErrMisconfiguration, "code is not set")
	}

	if err := c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, resp.GetCode(), ar); err != nil {
		return errors.Wrap(ErrServerError, err.Error())
	}

	return nil
}
