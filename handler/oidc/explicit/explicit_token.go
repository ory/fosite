package explicit

import (
	"net/http"

	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/oidc"
	"github.com/ory-am/fosite/handler/oidc/common"
	"golang.org/x/net/context"
)

func (c *OpenIDConnectExplicitHandler) ValidateTokenEndpointRequest(ctx context.Context, r *http.Request, request AccessRequester) error {
	return nil
}

func (c *OpenIDConnectExplicitHandler) HandleTokenEndpointRequest(ctx context.Context, req *http.Request, requester AccessRequester, responder AccessResponder) error {
	if !requester.GetGrantTypes().Exact("authorization_code") {
		return nil
	}

	if err := c.OpenIDConnectRequestStorage.IsOpenIDConnectSession(req.PostForm.Get("code")); err != oidc.ErrNoSessionFound {
		return nil
	} else if err != nil {
		return errors.New(ErrServerError)
	}

	return common.IssueIDToken(c.OpenIDConnectTokenStrategy, ctx, req, requester, responder)
}
