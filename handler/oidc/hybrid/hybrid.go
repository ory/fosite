package hybrid

import (
	"net/http"

	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/ory-am/fosite/handler/core/implicit"
	"github.com/ory-am/fosite/handler/oidc"
	"golang.org/x/net/context"
)

type OpenIDConnectHybridHandler struct {
	*implicit.AuthorizeImplicitGrantTypeHandler
	*explicit.AuthorizeExplicitGrantTypeHandler
	*oidc.IDTokenHandleHelper
}

func (c *OpenIDConnectHybridHandler) HandleAuthorizeEndpointRequest(ctx context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) error {
	if len(ar.GetResponseTypes()) < 2 {
		return nil
	}

	if !(ar.GetResponseTypes().Matches("token", "id_token", "code") || ar.GetResponseTypes().Matches("token", "code")) {
		return nil
	}

	if ar.GetResponseTypes().Has("code") {
		code, signature, err := c.AuthorizeCodeStrategy.GenerateAuthorizeCode(ctx, req, ar)
		if err != nil {
			return errors.New(ErrServerError)
		}

		if err := c.AuthorizeCodeGrantStorage.CreateAuthorizeCodeSession(ctx, signature, ar); err != nil {
			return errors.New(ErrServerError)
		}

		resp.AddFragment("code", code)
		resp.AddFragment("state", ar.GetState())
		ar.SetResponseTypeHandled("code")
	}

	if ar.GetResponseTypes().Has("token") {
		if err := c.IssueImplicitAccessToken(ctx, req, ar, resp); err != nil {
			return errors.New(err)
		}
		ar.SetResponseTypeHandled("token")
	}

	if !ar.GetScopes().Has("openid") {
		return nil
	}

	err := c.IssueImplicitIDToken(ctx, req, ar, resp)
	if err != nil {
		return errors.New(err)
	}

	ar.SetResponseTypeHandled("id_token")
	return nil
}
