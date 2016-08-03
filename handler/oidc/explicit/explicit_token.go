package explicit

import (
	"net/http"

	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/oidc"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

func (c *OpenIDConnectExplicitHandler) HandleTokenEndpointRequest(ctx context.Context, r *http.Request, request AccessRequester) error {
	return ErrUnknownRequest
}

func (c *OpenIDConnectExplicitHandler) PopulateTokenEndpointResponse(ctx context.Context, req *http.Request, requester AccessRequester, responder AccessResponder) error {
	if !requester.GetGrantTypes().Exact("authorization_code") {
		return errors.Wrap(ErrUnknownRequest, "")
	}

	authorize, err := c.OpenIDConnectRequestStorage.GetOpenIDConnectSession(ctx, requester.GetRequestForm().Get("code"), requester)
	if err == oidc.ErrNoSessionFound {
		return errors.Wrap(ErrUnknownRequest, err.Error())
	} else if err != nil {
		return errors.Wrap(ErrServerError, err.Error())
	}

	if !authorize.GetRequestedScopes().Has("openid") {
		return errors.Wrap(ErrUnknownRequest, "")
	}

	if !requester.GetClient().GetGrantTypes().Has("authorization_code") {
		return errors.Wrap(ErrInvalidGrant, "")
	}

	if !requester.GetClient().GetResponseTypes().Has("id_token") {
		return errors.Wrap(ErrInvalidGrant, "")
	}

	return c.IssueExplicitIDToken(ctx, req, authorize, responder)
}
