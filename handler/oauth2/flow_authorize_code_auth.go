/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package oauth2

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
)

// AuthorizeExplicitGrantTypeHandler is a response handler for the Authorize Code grant using the explicit grant type
// as defined in https://tools.ietf.org/html/rfc6749#section-4.1
type AuthorizeExplicitGrantHandler struct {
	AccessTokenStrategy   AccessTokenStrategy
	RefreshTokenStrategy  RefreshTokenStrategy
	AuthorizeCodeStrategy AuthorizeCodeStrategy
	CoreStorage           CoreStorage
	//TokenRevocationStorage TokenRevocationStorage

	// AuthCodeLifespan defines the lifetime of an authorize code.
	AuthCodeLifespan time.Duration

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration

	// RefreshTokenLifespan defines the lifetime of a refresh token. Leave to 0 for unlimited lifetime.
	RefreshTokenLifespan time.Duration

	ScopeStrategy            fosite.ScopeStrategy
	AudienceMatchingStrategy fosite.AudienceMatchingStrategy

	// SanitationWhiteList is a whitelist of form values that are required by the token endpoint. These values
	// are safe for storage in a database (cleartext).
	SanitationWhiteList []string

	TokenRevocationStorage TokenRevocationStorage

	IsRedirectURISecure func(*url.URL) bool

	RefreshTokenScopes []string
}

func (c *AuthorizeExplicitGrantHandler) secureChecker() func(*url.URL) bool {
	if c.IsRedirectURISecure == nil {
		c.IsRedirectURISecure = fosite.IsRedirectURISecure
	}
	return c.IsRedirectURISecure
}

func (c *AuthorizeExplicitGrantHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	// This let's us define multiple response types, for example open id connect's id_token
	if !ar.GetResponseTypes().ExactOne("code") {
		return nil
	}

	// Disabled because this is already handled at the authorize_request_handler
	// if !ar.GetClient().GetResponseTypes().Has("code") {
	// 	 return errors.WithStack(fosite.ErrInvalidGrant)
	// }

	if !c.secureChecker()(ar.GetRedirectURI()) {
		return errors.WithStack(fosite.ErrInvalidRequest.WithHint("Redirect URL is using an insecure protocol, http is only allowed for hosts with suffix `localhost`, for example: http://myapp.localhost/."))
	}

	client := ar.GetClient()
	for _, scope := range ar.GetRequestedScopes() {
		if !c.ScopeStrategy(client.GetScopes(), scope) {
			return errors.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope \"%s\".", scope))
		}
	}

	if err := c.AudienceMatchingStrategy(client.GetAudience(), ar.GetRequestedAudience()); err != nil {
		return err
	}

	return c.IssueAuthorizeCode(ctx, ar, resp)
}

func (c *AuthorizeExplicitGrantHandler) IssueAuthorizeCode(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	code, signature, err := c.AuthorizeCodeStrategy.GenerateAuthorizeCode(ctx, ar)
	if err != nil {
		return errors.WithStack(fosite.ErrServerError.WithCause(err).WithDebug(err.Error()))
	}

	ar.GetSession().SetExpiresAt(fosite.AuthorizeCode, time.Now().UTC().Add(c.AuthCodeLifespan))
	if err := c.CoreStorage.CreateAuthorizeCodeSession(ctx, signature, ar.Sanitize(c.GetSanitationWhiteList())); err != nil {
		return errors.WithStack(fosite.ErrServerError.WithCause(err).WithDebug(err.Error()))
	}
	if ar.GetRequestForm().Get("response_mode") == "form_post" {
		resp.AddForm("code", code)
		resp.AddForm("state", ar.GetState())
		resp.AddForm("scope", strings.Join(ar.GetGrantedScopes(), " "))
	} else {
		resp.AddQuery("code", code)
		resp.AddQuery("state", ar.GetState())
		resp.AddQuery("scope", strings.Join(ar.GetGrantedScopes(), " "))
	}
	ar.SetResponseTypeHandled("code")
	return nil
}

func (c *AuthorizeExplicitGrantHandler) GetSanitationWhiteList() []string {
	if len(c.SanitationWhiteList) > 0 {
		return c.SanitationWhiteList
	}
	return []string{
		"code",
		"redirect_uri",
	}
}
