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

package openid

import (
	"fmt"

	"context"
	"encoding/base64"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
)

type OpenIDConnectHybridHandler struct {
	AuthorizeImplicitGrantTypeHandler *oauth2.AuthorizeImplicitGrantTypeHandler
	AuthorizeExplicitGrantHandler     *oauth2.AuthorizeExplicitGrantHandler
	IDTokenHandleHelper               *IDTokenHandleHelper
	ScopeStrategy                     fosite.ScopeStrategy

	Enigma *jwt.RS256JWTStrategy
}

func (c *OpenIDConnectHybridHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	if len(ar.GetResponseTypes()) < 2 {
		return nil
	}

	if !(ar.GetResponseTypes().Equals("token", "id_token", "code") || ar.GetResponseTypes().Equals("token", "code") || ar.GetResponseTypes().Equals("id_token", "code")) {
		return nil
	}

	if ar.GetResponseTypes().Equals("token") && !ar.GetClient().GetResponseTypes().HasAll("token") {
		return errors.WithStack(fosite.ErrInvalidGrant.WithDebug("The client is not allowed to use the token response type"))
	} else if ar.GetResponseTypes().Equals("code") && !ar.GetClient().GetResponseTypes().HasAll("code") {
		return errors.WithStack(fosite.ErrInvalidGrant.WithDebug("The client is not allowed to use the code response type"))
	} else if ar.GetResponseTypes().Equals("id_token") && !ar.GetClient().GetResponseTypes().HasAll("id_token") {
		return errors.WithStack(fosite.ErrInvalidGrant.WithDebug("The client is not allowed to use the id_token response type"))
	}

	sess, ok := ar.GetSession().(Session)
	if !ok {
		return errors.WithStack(ErrInvalidSession)
	}

	client := ar.GetClient()
	for _, scope := range ar.GetRequestedScopes() {
		if !c.ScopeStrategy(client.GetScopes(), scope) {
			return errors.WithStack(fosite.ErrInvalidScope.WithDebug(fmt.Sprintf("The client is not allowed to request scope %s", scope)))
		}
	}

	claims := sess.IDTokenClaims()
	if ar.GetResponseTypes().HasAll("code") {
		if !ar.GetClient().GetGrantTypes().HasAll("authorization_code") {
			return errors.WithStack(fosite.ErrInvalidGrant.WithDebug("The client is not allowed to use the authorization_code grant type"))
		}

		code, signature, err := c.AuthorizeExplicitGrantHandler.AuthorizeCodeStrategy.GenerateAuthorizeCode(ctx, ar)
		if err != nil {
			return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
		} else if err := c.AuthorizeExplicitGrantHandler.CoreStorage.CreateAuthorizeCodeSession(ctx, signature, ar); err != nil {
			return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
		}

		resp.AddFragment("code", code)
		ar.SetResponseTypeHandled("code")

		hash, err := c.Enigma.Hash([]byte(resp.GetFragment().Get("code")))
		if err != nil {
			return err
		}
		claims.CodeHash = base64.RawURLEncoding.EncodeToString([]byte(hash[:c.Enigma.GetSigningMethodLength()/2]))
	}

	if ar.GetResponseTypes().HasAll("token") {
		if !ar.GetClient().GetGrantTypes().HasAll("implicit") {
			return errors.WithStack(fosite.ErrInvalidGrant.WithDebug("The client is not allowed to use the implicit grant type"))
		} else if err := c.AuthorizeImplicitGrantTypeHandler.IssueImplicitAccessToken(ctx, ar, resp); err != nil {
			return errors.WithStack(err)
		}
		ar.SetResponseTypeHandled("token")

		hash, err := c.Enigma.Hash([]byte(resp.GetFragment().Get("access_token")))
		if err != nil {
			return err
		}
		claims.AccessTokenHash = base64.RawURLEncoding.EncodeToString([]byte(hash[:c.Enigma.GetSigningMethodLength()/2]))
	}

	if resp.GetFragment().Get("state") == "" {
		resp.AddFragment("state", ar.GetState())
	}

	if !ar.GetGrantedScopes().HasAll("openid") || !ar.GetResponseTypes().HasAll("id_token") {
		ar.SetResponseTypeHandled("id_token")
		return nil
	}

	if err := c.IDTokenHandleHelper.IssueImplicitIDToken(ctx, ar, resp); err != nil {
		return errors.WithStack(err)
	}

	ar.SetResponseTypeHandled("id_token")
	return nil
	// there is no need to check for https, because implicit flow does not require https
	// https://tools.ietf.org/html/rfc6819#section-4.4.2
}
