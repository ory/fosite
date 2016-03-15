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

	if !(ar.GetResponseTypes().Matches("token", "id_token", "code") || ar.GetResponseTypes().Matches("token", "id_token") || ar.GetResponseTypes().Matches("token", "code")) {
		return nil
	}

	if ar.GetResponseTypes().Has("code") {
		if err := explicit.IssueAuthorizeCode(ctx, c.AuthorizeCodeStrategy, c.ExplicitAuthorizeGrantStorage, req, ar, resp); err != nil {
			return err
		}
	}

	if ar.GetResponseTypes().Has("token") {
		if err := implicit.IssueImplicitAccessToken(ctx, c.AccessTokenStrategy, c.ImplicitAuthorizeGrantStorage, c.AccessTokenLifespan, req, ar, resp); err != nil {
			return err
		}
	}

	if !ar.GetScopes().Has("openid") {
		return nil
	}

	return common.IssueImplicitIDToken(ctx, c.OpenIDConnectTokenStrategy, req, ar, resp)
}
