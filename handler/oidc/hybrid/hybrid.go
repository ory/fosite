package hybrid

import (
	"net/http"
	"time"

	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/ory-am/fosite/handler/core/implicit"
	. "github.com/ory-am/fosite/handler/oidc"
	"github.com/ory-am/fosite/handler/oidc/common"
	"golang.org/x/net/context"
)

type OpenIDConnectHybridHandler struct {
	// OpenIDConnectTokenStrategy is the strategy for generating id tokens.
	OpenIDConnectTokenStrategy OpenIDConnectTokenStrategy

	// ImplicitGrantStorage is used to persist session data across requests.
	ExplicitAuthorizeGrantStorage explicit.AuthorizeCodeGrantStorage

	// ImplicitGrantStorage is used to persist session data across requests.
	ImplicitAuthorizeGrantStorage implicit.ImplicitGrantStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration

	AccessTokenStrategy core.AccessTokenStrategy

	AuthorizeCodeStrategy core.AuthorizeCodeStrategy
}

func (c *OpenIDConnectHybridHandler) HandleAuthorizeEndpointRequest(ctx context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) error {
	if len(ar.GetResponseTypes()) < 2 {
		return nil
	}

	if !(ar.GetResponseTypes().Is("token", "id_token", "code") || ar.GetResponseTypes().Is("token", "id_token") || ar.GetResponseTypes().Is("token", "code")) {
		return nil
	}

	if ar.GetResponseTypes().Has("code") {
		if err := explicit.IssueAuthorizeCode(c.AuthorizeCodeStrategy, c.ExplicitAuthorizeGrantStorage, ctx, req, ar, resp); err != nil {
			return err
		}
	}

	if ar.GetResponseTypes().Has("token") {
		if err := implicit.IssueImplicitAccessToken(c.AccessTokenStrategy, c.ImplicitAuthorizeGrantStorage, c.AccessTokenLifespan, ctx, req, ar, resp); err != nil {
			return err
		}
	}

	if !ar.GetScopes().Has("openid") {
		return nil
	}

	return common.IssueIDToken(c.OpenIDConnectTokenStrategy, ctx, req, ar, resp)
}
