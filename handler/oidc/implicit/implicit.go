package implicit

import (
	"net/http"

	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core/implicit"
	. "github.com/ory-am/fosite/handler/oidc"
	"golang.org/x/net/context"
	"github.com/ory-am/fosite/token/jwt"
)

type OpenIDConnectImplicitHandler struct {
	*implicit.AuthorizeImplicitGrantTypeHandler
	*IDTokenHandleHelper

	Enigma *jwt.Enigma
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

	hash, err := c.Enigma.Hash([]byte(resp.GetFragment().Get("access_token")))
	if err != nil {
		return err
	}
	if err = c.IssueImplicitIDToken(ctx, req, ar, resp, map[string]interface{}{
		"at_hash": hash[:c.Enigma.GetSigningMethodLength() / 2],
	}); err != nil {
		return errors.New(err)
	}

	ar.SetResponseTypeHandled("id_token")
	return nil
}
