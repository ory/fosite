package hybrid

import (
	"net/http"

	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/ory-am/fosite/handler/core/implicit"
	"github.com/ory-am/fosite/handler/oidc"
	"github.com/ory-am/fosite/handler/oidc/strategy"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/pkg/errors"
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

	if !ar.GetClient().GetResponseTypes().Has("token", "code") {
		return errors.Wrap(ErrInvalidGrant, "")
	} else if ar.GetResponseTypes().Matches("id_token") && !ar.GetClient().GetResponseTypes().Has("id_token") {
		return errors.Wrap(ErrInvalidGrant, "")
	}

	sess, ok := ar.GetSession().(strategy.Session)
	if !ok {
		return errors.Wrap(oidc.ErrInvalidSession, "")
	}

	claims := sess.IDTokenClaims()

	if ar.GetResponseTypes().Has("code") {
		if !ar.GetClient().GetGrantTypes().Has("authorization_code") {
			return errors.Wrap(ErrInvalidGrant, "")
		}

		code, signature, err := c.AuthorizeCodeStrategy.GenerateAuthorizeCode(ctx, ar)
		if err != nil {
			return errors.Wrap(ErrServerError, err.Error())
		} else if err := c.AuthorizeCodeGrantStorage.CreateAuthorizeCodeSession(ctx, signature, ar); err != nil {
			return errors.Wrap(ErrServerError, err.Error())
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
		if !ar.GetClient().GetGrantTypes().Has("implicit") {
			return errors.Wrap(ErrInvalidGrant, "")
		} else if err := c.IssueImplicitAccessToken(ctx, req, ar, resp); err != nil {
			return errors.Wrap(err, err.Error())
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
		return errors.Wrap(err, err.Error())
	} else if err := c.IssueImplicitIDToken(ctx, req, ar, resp); err != nil {
		return errors.Wrap(err, err.Error())
	}

	ar.SetResponseTypeHandled("id_token")
	return nil
}
