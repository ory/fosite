// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"strings"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
)

var _ fosite.AuthorizeEndpointHandler = (*NoneResponseTypeHandler)(nil)

// NoneResponseTypeHandler is a response handler for when the None response type is requested
// as defined in https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none
type NoneResponseTypeHandler struct {
	Config interface {
		fosite.ScopeStrategyProvider
		fosite.AudienceStrategyProvider
		fosite.RedirectSecureCheckerProvider
		fosite.OmitRedirectScopeParamProvider
	}
}

func (c *NoneResponseTypeHandler) secureChecker(ctx context.Context) func(context.Context, *url.URL) bool {
	if c.Config.GetRedirectSecureChecker(ctx) == nil {
		return fosite.IsRedirectURISecure
	}
	return c.Config.GetRedirectSecureChecker(ctx)
}

func (c *NoneResponseTypeHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	if !ar.GetResponseTypes().ExactOne("none") {
		return nil
	}

	ar.SetDefaultResponseMode(fosite.ResponseModeQuery)

	if !c.secureChecker(ctx)(ctx, ar.GetRedirectURI()) {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Redirect URL is using an insecure protocol, http is only allowed for hosts with suffix 'localhost', for example: http://myapp.localhost/."))
	}

	client := ar.GetClient()
	for _, scope := range ar.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errorsx.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	if err := c.Config.GetAudienceStrategy(ctx)(client.GetAudience(), ar.GetRequestedAudience()); err != nil {
		return err
	}

	resp.AddParameter("state", ar.GetState())
	if !c.Config.GetOmitRedirectScopeParam(ctx) {
		resp.AddParameter("scope", strings.Join(ar.GetGrantedScopes(), " "))
	}
	ar.SetResponseTypeHandled("none")
	return nil
}
