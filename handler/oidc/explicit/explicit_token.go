package explicit

import (
	"net/http"

	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/oidc"
	"golang.org/x/net/context"
)

func (c *OpenIDConnectExplicitHandler) HandleTokenEndpointRequest(ctx context.Context, r *http.Request, request AccessRequester) error {
	return ErrUnknownRequest
}

func (c *OpenIDConnectExplicitHandler) PopulateTokenEndpointResponse(ctx context.Context, req *http.Request, requester AccessRequester, responder AccessResponder) error {
	if !requester.GetGrantTypes().Exact("authorization_code") {
		return ErrUnknownRequest
	}

	authorize, err := c.OpenIDConnectRequestStorage.GetOpenIDConnectSession(ctx, requester.GetRequestForm().Get("code"), requester)
	if err == oidc.ErrNoSessionFound {
		return ErrUnknownRequest
	} else if err != nil {
		return errors.New(ErrServerError)
	}

	if !authorize.GetScopes().Has("openid") {
		return ErrUnknownRequest
	}

	return c.IssueExplicitIDToken(ctx, req, authorize, responder, map[string]interface{}{})
}
