package hybrid

import (
	"net/http"

	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/ory-am/fosite/handler/core/implicit"
	"github.com/ory-am/fosite/handler/oidc"
	"github.com/ory-am/fosite/handler/oidc/strategy"
	"github.com/ory-am/fosite/token/jwt"
	"golang.org/x/net/context"
)

type OpenIDConnectHybridHandler struct {
	*implicit.AuthorizeImplicitGrantTypeHandler
	*explicit.AuthorizeExplicitGrantTypeHandler
	*oidc.IDTokenHandleHelper

	Enigma *jwt.RS256JWTStrategy
}

func (c *OpenIDConnectHybridHandler) HandleAuthorizeEndpointRequest(ctx context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) error {
	if len(ar.GetResponseTypes()) < 2 {
		return nil
	}

	if !(ar.GetResponseTypes().Matches("token", "id_token", "code") || ar.GetResponseTypes().Matches("token", "code")) {
		return nil
	}

	sess, ok := ar.GetSession().(strategy.Session)
	if !ok {
		return errors.New("Session must be of type strategy.Session")
	}

	claims := sess.IDTokenClaims()

	if ar.GetResponseTypes().Has("code") {
		code, signature, err := c.AuthorizeCodeStrategy.GenerateAuthorizeCode(ctx, ar)
		if err != nil {
			return errors.New(ErrServerError)
		}

		if err := c.AuthorizeCodeGrantStorage.CreateAuthorizeCodeSession(ctx, signature, ar); err != nil {
			return errors.New(ErrServerError)
		}

		resp.AddFragment("code", code)
		resp.AddFragment("state", ar.GetState())
		ar.SetResponseTypeHandled("code")

		hash, err := c.Enigma.Hash([]byte(resp.GetFragment().Get("code")))
		if err != nil {
			return err
		}
		claims.CodeHash = hash[:c.Enigma.GetSigningMethodLength()/2]
	}

	if ar.GetResponseTypes().Has("token") {
		if err := c.IssueImplicitAccessToken(ctx, req, ar, resp); err != nil {
			return errors.New(err)
		}
		ar.SetResponseTypeHandled("token")

		hash, err := c.Enigma.Hash([]byte(resp.GetFragment().Get("access_token")))
		if err != nil {
			return err
		}
		claims.AccessTokenHash = hash[:c.Enigma.GetSigningMethodLength()/2]
	}

	if !ar.GetScopes().Has("openid") {
		return nil
	}

	if err := c.IssueImplicitIDToken(ctx, req, ar, resp); err != nil {
		return errors.New(err)
	}

	err := c.IssueImplicitIDToken(ctx, req, ar, resp)
	if err != nil {
		return errors.New(err)
	}

	ar.SetResponseTypeHandled("id_token")
	return nil
}
