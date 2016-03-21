package implicit

import (
	"net/http"
	. "github.com/ory-am/fosite"
	. "github.com/ory-am/fosite/handler/oidc"
	"golang.org/x/net/context"
	"github.com/ory-am/fosite/handler/core/implicit"
	"github.com/go-errors/errors"
)

type OpenIDConnectImplicitHandler struct {
	*implicit.AuthorizeImplicitGrantTypeHandler
	*IDTokenHandleHelper
}

func (c *OpenIDConnectImplicitHandler) HandleAuthorizeEndpointRequest(ctx context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) error {
	if !(ar.GetScopes().Has("openid") && (ar.GetResponseTypes().Matches("token", "id_token") || ar.GetResponseTypes().Exact("id_token"))) {
		return nil
	}

	if ar.GetResponseTypes().Has("token") {
		if err := c.IssueImplicitAccessToken(ctx, req, ar, resp); err != nil {
			return errors.New(err)
		}
		ar.SetResponseTypeHandled("token")
	}

	err := c.IssueImplicitIDToken(ctx, req, ar, resp)
	if err != nil {
		return errors.New(err)
	}

	ar.SetResponseTypeHandled("id_token")
	return nil
}
