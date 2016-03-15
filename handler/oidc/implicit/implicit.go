package implicit

import (
	"net/http"
	. "github.com/ory-am/fosite"
	. "github.com/ory-am/fosite/handler/oidc"
	"golang.org/x/net/context"
	"github.com/ory-am/fosite/handler/core/implicit"
)

type OpenIDConnectImplicitHandler struct {
	// OpenIDConnectTokenStrategy is the strategy for generating id tokens.
	OpenIDConnectTokenStrategy OpenIDConnectTokenStrategy

	implicit.AuthorizeImplicitGrantTypeHandler
	IDTokenHandleHelper
}

func (c *OpenIDConnectImplicitHandler) HandleAuthorizeEndpointRequest(ctx context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) error {
	if !(ar.GetScopes().Has("openid") && (ar.GetResponseTypes().Matches("token", "id_token") || ar.GetResponseTypes().Exact("id_token"))) {
		return nil
	}

	if ar.GetResponseTypes().Has("token") {
		if err := c.IssueImplicitAccessToken(ctx, req, ar, resp); err != nil {
			return err
		}
	}

	return c.IssueImplicitIDToken(ctx, req, ar, resp)
}
