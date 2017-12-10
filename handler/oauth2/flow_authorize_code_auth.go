// Copyright © 2017 Aeneas Rekkas <aeneas+oss@aeneas.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oauth2

import (
	"strings"
	"time"

	"fmt"

	"context"

	"github.com/ory/fosite"
	"github.com/pkg/errors"
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

	ScopeStrategy fosite.ScopeStrategy
}

func (c *AuthorizeExplicitGrantHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	// This let's us define multiple response types, for example open id connect's id_token
	if !ar.GetResponseTypes().Exact("code") {
		return nil
	}

	if !ar.GetClient().GetResponseTypes().Has("code") {
		return errors.WithStack(fosite.ErrInvalidGrant)
	}

	if !fosite.IsRedirectURISecure(ar.GetRedirectURI()) {
		return errors.WithStack(fosite.ErrInvalidRequest.WithDebug("Redirect URL is using an insecure protocol, http is only allowed for hosts with suffix `localhost`, for example: http://myapp.localhost/"))
	}

	client := ar.GetClient()
	for _, scope := range ar.GetRequestedScopes() {
		if !c.ScopeStrategy(client.GetScopes(), scope) {
			return errors.WithStack(fosite.ErrInvalidScope.WithDebug(fmt.Sprintf("The client is not allowed to request scope %s", scope)))
		}
	}

	return c.IssueAuthorizeCode(ctx, ar, resp)
}

func (c *AuthorizeExplicitGrantHandler) IssueAuthorizeCode(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	code, signature, err := c.AuthorizeCodeStrategy.GenerateAuthorizeCode(ctx, ar)
	if err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	}

	ar.GetSession().SetExpiresAt(fosite.AuthorizeCode, time.Now().UTC().Add(c.AuthCodeLifespan))
	if err := c.CoreStorage.CreateAuthorizeCodeSession(ctx, signature, ar); err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	}

	resp.AddQuery("code", code)
	resp.AddQuery("state", ar.GetState())
	resp.AddQuery("scope", strings.Join(ar.GetGrantedScopes(), " "))
	ar.SetResponseTypeHandled("code")
	return nil
}
