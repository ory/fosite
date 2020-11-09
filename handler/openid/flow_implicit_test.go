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

package openid

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
)

func makeOpenIDConnectImplicitHandler(minParameterEntropy int) OpenIDConnectImplicitHandler {
	var idStrategy = &DefaultStrategy{
		JWTStrategy: &jwt.RS256JWTStrategy{
			PrivateKey: internal.MustRSAKey(),
		},
		MinParameterEntropy: minParameterEntropy,
	}

	var j = &DefaultStrategy{
		JWTStrategy: &jwt.RS256JWTStrategy{
			PrivateKey: key,
		},
		MinParameterEntropy: minParameterEntropy,
	}

	return OpenIDConnectImplicitHandler{
		AuthorizeImplicitGrantTypeHandler: &oauth2.AuthorizeImplicitGrantTypeHandler{
			AccessTokenLifespan: time.Hour,
			AccessTokenStrategy: hmacStrategy,
			AccessTokenStorage:  storage.NewMemoryStore(),
		},
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: idStrategy,
		},
		ScopeStrategy:                 fosite.HierarchicScopeStrategy,
		OpenIDConnectRequestValidator: NewOpenIDConnectRequestValidator(nil, j.JWTStrategy),
		MinParameterEntropy:           minParameterEntropy,
	}
}

func TestImplicit_HandleAuthorizeEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	aresp := fosite.NewAuthorizeResponse()
	areq := fosite.NewAuthorizeRequest()
	areq.Session = new(fosite.DefaultSession)

	for k, c := range []struct {
		description string
		setup       func() OpenIDConnectImplicitHandler
		expectErr   error
		check       func()
	}{
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				return makeOpenIDConnectImplicitHandler(fosite.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = fosite.Arguments{"id_token"}
				areq.State = "foostate"
				return makeOpenIDConnectImplicitHandler(fosite.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = fosite.Arguments{"token", "id_token"}
				return makeOpenIDConnectImplicitHandler(fosite.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = fosite.Arguments{}
				areq.GrantedScope = fosite.Arguments{"openid"}
				return makeOpenIDConnectImplicitHandler(fosite.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = fosite.Arguments{"token", "id_token"}
				areq.RequestedScope = fosite.Arguments{"openid"}
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{},
					ResponseTypes: fosite.Arguments{},
					Scopes:        []string{"openid", "fosite"},
				}
				return makeOpenIDConnectImplicitHandler(fosite.MinParameterEntropy)
			},
			expectErr: fosite.ErrInvalidGrant,
		},
		// Disabled because this is already handled at the authorize_request_handler
		//{
		//	description: "should not do anything because request requirements are not met",
		//	setup: func() OpenIDConnectImplicitHandler {
		//		areq.ResponseTypes = fosite.Arguments{"token", "id_token"}
		//		areq.RequestedScope = fosite.Arguments{"openid"}
		//		areq.Client = &fosite.DefaultClient{
		//			GrantTypes:    fosite.Arguments{"implicit"},
		//			ResponseTypes: fosite.Arguments{},
		//			RequestedScope:        []string{"openid", "fosite"},
		//		}
		//		return makeOpenIDConnectImplicitHandler(fosite.MinParameterEntropy)
		//	},
		//	expectErr: fosite.ErrInvalidGrant,
		//},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = fosite.Arguments{"id_token"}
				areq.RequestedScope = fosite.Arguments{"openid"}
				areq.Client = &fosite.DefaultClient{
					GrantTypes: fosite.Arguments{"implicit"},
					//ResponseTypes: fosite.Arguments{"token", "id_token"},
					Scopes: []string{"openid", "fosite"},
				}
				return makeOpenIDConnectImplicitHandler(fosite.MinParameterEntropy)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() OpenIDConnectImplicitHandler {
				areq.Form = url.Values{"nonce": {"short"}}
				areq.ResponseTypes = fosite.Arguments{"id_token"}
				areq.RequestedScope = fosite.Arguments{"openid"}
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"implicit"},
					ResponseTypes: fosite.Arguments{"token", "id_token"},
					Scopes:        []string{"openid", "fosite"},
				}
				return makeOpenIDConnectImplicitHandler(fosite.MinParameterEntropy)
			},
			expectErr: fosite.ErrInsufficientEntropy,
		},
		{
			description: "should fail because session not set",
			setup: func() OpenIDConnectImplicitHandler {
				areq.Form = url.Values{"nonce": {"long-enough"}}
				areq.ResponseTypes = fosite.Arguments{"id_token"}
				areq.RequestedScope = fosite.Arguments{"openid"}
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"implicit"},
					ResponseTypes: fosite.Arguments{"token", "id_token"},
					Scopes:        []string{"openid", "fosite"},
				}
				return makeOpenIDConnectImplicitHandler(fosite.MinParameterEntropy)
			},
			expectErr: ErrInvalidSession,
		},
		{
			description: "should pass because nonce set",
			setup: func() OpenIDConnectImplicitHandler {
				areq.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
					Subject: "peter",
				}
				areq.Form.Add("nonce", "some-random-foo-nonce-wow")
				return makeOpenIDConnectImplicitHandler(fosite.MinParameterEntropy)
			},
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = fosite.Arguments{"id_token"}
				return makeOpenIDConnectImplicitHandler(fosite.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get("id_token"))
				assert.NotEmpty(t, aresp.GetParameters().Get("state"))
				assert.Empty(t, aresp.GetParameters().Get("access_token"))
			},
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = fosite.Arguments{"token", "id_token"}
				return makeOpenIDConnectImplicitHandler(fosite.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get("id_token"))
				assert.NotEmpty(t, aresp.GetParameters().Get("state"))
				assert.NotEmpty(t, aresp.GetParameters().Get("access_token"))
			},
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectImplicitHandler {
				areq.ResponseTypes = fosite.Arguments{"id_token", "token"}
				areq.RequestedScope = fosite.Arguments{"fosite", "openid"}
				return makeOpenIDConnectImplicitHandler(fosite.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get("id_token"))
				assert.NotEmpty(t, aresp.GetParameters().Get("state"))
				assert.NotEmpty(t, aresp.GetParameters().Get("access_token"))
				assert.Equal(t, fosite.ResponseModeFragment, areq.GetResponseMode())
			},
		},
		{
			description: "should pass with low min entropy",
			setup: func() OpenIDConnectImplicitHandler {
				areq.Form.Set("nonce", "short")
				return makeOpenIDConnectImplicitHandler(4)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get("id_token"))
				assert.NotEmpty(t, aresp.GetParameters().Get("state"))
				assert.NotEmpty(t, aresp.GetParameters().Get("access_token"))
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			h := c.setup()
			err := h.HandleAuthorizeEndpointRequest(nil, areq, aresp)

			if c.expectErr != nil {
				assert.EqualError(t, err, c.expectErr.Error())
			} else {
				assert.NoError(t, err)
				if c.check != nil {
					c.check()
				}
			}
		})
	}
}
