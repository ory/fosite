package explicit

import (
	"net/http"

	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/oidc"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

func (c *OpenIDConnectExplicitHandler) HandleTokenEndpointRequest(ctx context.Context, r *http.Request, request AccessRequester) (context.Context, error) {
	return ctx, ErrUnknownRequest
}

func (c *OpenIDConnectExplicitHandler) PopulateTokenEndpointResponse(ctx context.Context, req *http.Request, requester AccessRequester, responder AccessResponder) (context.Context, error) {
	if !requester.GetGrantTypes().Exact("authorization_code") {
		return ctx, errors.Wrap(ErrUnknownRequest, "")
	}

	ctx, authorize, err := c.OpenIDConnectRequestStorage.GetOpenIDConnectSession(ctx, requester.GetRequestForm().Get("code"), requester)
	if err == oidc.ErrNoSessionFound {
		return ctx, errors.Wrap(ErrUnknownRequest, err.Error())
	} else if err != nil {
		return ctx, errors.Wrap(ErrServerError, err.Error())
	}

	if !authorize.GetScopes().Has("openid") {
		return ctx, errors.Wrap(ErrUnknownRequest, "")
	}

	if !requester.GetClient().GetGrantTypes().Has("authorization_code") {
		return ctx, errors.Wrap(ErrInvalidGrant, "")
	}

	if !requester.GetClient().GetResponseTypes().Has("id_token") {
		return ctx, errors.Wrap(ErrInvalidGrant, "")
	}

	return ctx, c.IssueExplicitIDToken(ctx, req, authorize, responder)
}
