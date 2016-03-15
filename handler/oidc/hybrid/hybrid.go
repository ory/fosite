package hybrid

import (
	"net/http"

	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/ory-am/fosite/handler/core/implicit"
	"github.com/ory-am/fosite/handler/oidc"
	"golang.org/x/net/context"
)

type OpenIDConnectHybridHandler struct {
	implicit.AuthorizeImplicitGrantTypeHandler
	explicit.AuthorizeExplicitGrantTypeHandler
	oidc.IDTokenHandleHelper
}

func (c *OpenIDConnectHybridHandler) HandleAuthorizeEndpointRequest(ctx context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) error {
	if len(ar.GetResponseTypes()) < 2 {
		return nil
	}

	if !(ar.GetResponseTypes().Matches("token", "id_token", "code") || ar.GetResponseTypes().Matches("token", "id_token") || ar.GetResponseTypes().Matches("token", "code")) {
		return nil
	}

	if ar.GetResponseTypes().Has("code") {
		if err := c.IssueAuthorizeCode(ctx, req, ar, resp); err != nil {
			return err
		}
	}

	if ar.GetResponseTypes().Has("token") {
		if err := c.IssueImplicitAccessToken(ctx, req, ar, resp); err != nil {
			return err
		}
	}

	if !ar.GetScopes().Has("openid") {
		return nil
	}

	return c.IssueImplicitIDToken(ctx, req, ar, resp)
}
