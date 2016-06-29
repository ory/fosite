package implicit

import (
	"net/http"

	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core/implicit"
	. "github.com/ory-am/fosite/handler/oidc"
	"github.com/ory-am/fosite/handler/oidc/strategy"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

type OpenIDConnectImplicitHandler struct {
	AuthorizeImplicitGrantTypeHandler *implicit.AuthorizeImplicitGrantTypeHandler
	*IDTokenHandleHelper

	RS256JWTStrategy *jwt.RS256JWTStrategy
}

func (c *OpenIDConnectImplicitHandler) HandleAuthorizeEndpointRequest(ctx context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) (context.Context, error) {
	if !(ar.GetScopes().Has("openid") && (ar.GetResponseTypes().Has("token", "id_token") || ar.GetResponseTypes().Exact("id_token"))) {
		return ctx, nil
	}

	if !ar.GetClient().GetGrantTypes().Has("implicit") {
		return ctx, errors.Wrap(ErrInvalidGrant, "")
	}

	if ar.GetResponseTypes().Exact("id_token") && !ar.GetClient().GetResponseTypes().Has("id_token") {
		return ctx, errors.Wrap(ErrInvalidGrant, "")
	} else if ar.GetResponseTypes().Matches("token", "id_token") && !ar.GetClient().GetResponseTypes().Has("token", "id_token") {
		return ctx, errors.Wrap(ErrInvalidGrant, "")
	}

	sess, ok := ar.GetSession().(strategy.Session)
	if !ok {
		return ctx, ErrInvalidSession
	}

	var err error
	claims := sess.IDTokenClaims()

	if ar.GetResponseTypes().Has("token") {
		if ctx, err = c.AuthorizeImplicitGrantTypeHandler.IssueImplicitAccessToken(ctx, req, ar, resp); err != nil {
			return ctx, errors.Wrap(err, err.Error())
		}

		ar.SetResponseTypeHandled("token")
		hash, err := c.RS256JWTStrategy.Hash([]byte(resp.GetFragment().Get("access_token")))
		if err != nil {
			return ctx, err
		}

		claims.AccessTokenHash = hash[:c.RS256JWTStrategy.GetSigningMethodLength()/2]
	}

	if err := c.IssueImplicitIDToken(ctx, req, ar, resp); err != nil {
		return ctx, errors.Wrap(err, err.Error())
	}

	ar.SetResponseTypeHandled("id_token")
	return ctx, nil
}
