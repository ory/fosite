package openid

import (
	"net/http"

	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"github.com/ory-am/fosite"
)

func (c *OpenIDConnectExplicitHandler) HandleTokenEndpointRequest(ctx context.Context, r *http.Request, request fosite.AccessRequester) error {
	return fosite.ErrUnknownRequest
}

func (c *OpenIDConnectExplicitHandler) PopulateTokenEndpointResponse(ctx context.Context, req *http.Request, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !requester.GetGrantTypes().Exact("authorization_code") {
		return errors.Wrap(fosite.ErrUnknownRequest, "")
	}

	authorize, err := c.OpenIDConnectRequestStorage.GetOpenIDConnectSession(ctx, requester.GetRequestForm().Get("code"), requester)
	if err == ErrNoSessionFound {
		return errors.Wrap(fosite.ErrUnknownRequest, err.Error())
	} else if err != nil {
		return errors.Wrap(fosite.ErrServerError, err.Error())
	}

	if !authorize.GetRequestedScopes().Has("openid") {
		return errors.Wrap(fosite.ErrUnknownRequest, "")
	}

	if !requester.GetClient().GetGrantTypes().Has("authorization_code") {
		return errors.Wrap(fosite.ErrInvalidGrant, "")
	}

	if !requester.GetClient().GetResponseTypes().Has("id_token") {
		return errors.Wrap(fosite.ErrInvalidGrant, "")
	}

	return c.IssueExplicitIDToken(ctx, req, authorize, responder)
}
