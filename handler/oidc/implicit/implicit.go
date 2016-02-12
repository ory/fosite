package implicit

import (
	"net/http"
	"time"

	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/handler/core/implicit"
	. "github.com/ory-am/fosite/handler/oidc"
	"github.com/ory-am/fosite/handler/oidc/common"
	"golang.org/x/net/context"
)

type OpenIDConnectImplicitHandler struct {
	// OpenIDConnectTokenStrategy is the strategy for generating id tokens.
	OpenIDConnectTokenStrategy OpenIDConnectTokenStrategy

	AccessTokenStrategy core.AccessTokenStrategy

	// ImplicitGrantStorage is used to persist session data across requests.
	ImplicitGrantStorage implicit.ImplicitGrantStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration
}

func (c *OpenIDConnectImplicitHandler) HandleAuthorizeEndpointRequest(ctx context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) error {
	if !(ar.GetScopes().Has("openid") && (ar.GetResponseTypes().Is("token", "id_token") || ar.GetResponseTypes().Exact("id_token"))) {
		return nil
	}

	if ar.GetResponseTypes().Has("token") {
		if err := implicit.IssueImplicitAccessToken(c.AccessTokenStrategy, c.ImplicitGrantStorage, c.AccessTokenLifespan, ctx, req, ar, resp); err != nil {
			return err
		}
	}

	return common.IssueIDToken(c.OpenIDConnectTokenStrategy, ctx, req, ar, resp)
}
