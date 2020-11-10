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
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/hmac"
	"github.com/ory/fosite/token/jwt"
)

var hmacStrategy = &oauth2.HMACSHAStrategy{
	Enigma: &hmac.HMACStrategy{
		GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows-nobody-knows"),
	},
}

type defaultSession struct {
	Claims  *jwt.IDTokenClaims
	Headers *jwt.Headers
	*fosite.DefaultSession
}

func makeOpenIDConnectHybridHandler(minParameterEntropy int) OpenIDConnectHybridHandler {
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

	return OpenIDConnectHybridHandler{
		AuthorizeExplicitGrantHandler: &oauth2.AuthorizeExplicitGrantHandler{
			AuthorizeCodeStrategy: hmacStrategy,
			AccessTokenLifespan:   time.Hour,
			AuthCodeLifespan:      time.Hour,
			RefreshTokenLifespan:  time.Hour,
			AccessTokenStrategy:   hmacStrategy,
			CoreStorage:           storage.NewMemoryStore(),
		},
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
		OpenIDConnectRequestStorage:   storage.NewMemoryStore(),
		MinParameterEntropy:           minParameterEntropy,
	}
}

func (s *defaultSession) IDTokenHeaders() *jwt.Headers {
	if s.Headers == nil {
		s.Headers = &jwt.Headers{}
	}
	return s.Headers
}

func (s *defaultSession) IDTokenClaims() *jwt.IDTokenClaims {
	if s.Claims == nil {
		s.Claims = &jwt.IDTokenClaims{}
	}
	return s.Claims
}

func TestHybrid_HandleAuthorizeEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	aresp := fosite.NewAuthorizeResponse()
	areq := fosite.NewAuthorizeRequest()

	for k, c := range []struct {
		description string
		setup       func() OpenIDConnectHybridHandler
		check       func()
		expectErr   error
	}{
		{
			description: "should not do anything because not a hybrid request",
			setup: func() OpenIDConnectHybridHandler {
				return makeOpenIDConnectHybridHandler(fosite.MinParameterEntropy)
			},
		},
		{
			description: "should not do anything because not a hybrid request",
			setup: func() OpenIDConnectHybridHandler {
				areq.ResponseTypes = fosite.Arguments{"token", "id_token"}
				return makeOpenIDConnectHybridHandler(fosite.MinParameterEntropy)
			},
		},
		{
			description: "should fail because nonce set but too short",
			setup: func() OpenIDConnectHybridHandler {
				areq.Form = url.Values{"nonce": {"short"}}
				areq.ResponseTypes = fosite.Arguments{"token", "code"}
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"authorization_code", "implicit"},
					ResponseTypes: fosite.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				areq.GrantedScope = fosite.Arguments{"openid"}
				return makeOpenIDConnectHybridHandler(fosite.MinParameterEntropy)
			},
			expectErr: fosite.ErrInsufficientEntropy,
		},
		{
			description: "should fail because nonce set but too short for non-default min entropy",
			setup: func() OpenIDConnectHybridHandler {
				areq.Form = url.Values{"nonce": {"some-foobar-nonce-win"}}
				areq.ResponseTypes = fosite.Arguments{"token", "code"}
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"authorization_code", "implicit"},
					ResponseTypes: fosite.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				areq.GrantedScope = fosite.Arguments{"openid"}
				return makeOpenIDConnectHybridHandler(42)
			},
			expectErr: fosite.ErrInsufficientEntropy,
		},
		{
			description: "should fail because session not given",
			setup: func() OpenIDConnectHybridHandler {
				areq.Form = url.Values{"nonce": {"long-enough"}}
				areq.ResponseTypes = fosite.Arguments{"token", "code"}
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"authorization_code", "implicit"},
					ResponseTypes: fosite.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				areq.GrantedScope = fosite.Arguments{"openid"}
				return makeOpenIDConnectHybridHandler(fosite.MinParameterEntropy)
			},
			expectErr: ErrInvalidSession,
		},
		{
			description: "should fail because client missing response types",
			setup: func() OpenIDConnectHybridHandler {
				areq.ResponseTypes = fosite.Arguments{"token", "code", "id_token"}
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"implicit"},
					ResponseTypes: fosite.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				areq.Session = &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
					Subject: "peter",
				}
				return makeOpenIDConnectHybridHandler(fosite.MinParameterEntropy)
			},
			expectErr: fosite.ErrInvalidGrant,
		},
		{
			description: "should pass because nonce was set with sufficient entropy",
			setup: func() OpenIDConnectHybridHandler {
				areq.Form.Set("nonce", "some-foobar-nonce-win")
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"authorization_code", "implicit"},
					ResponseTypes: fosite.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				return makeOpenIDConnectHybridHandler(fosite.MinParameterEntropy)
			},
		},
		{
			description: "should pass even if nonce was not set",
			setup: func() OpenIDConnectHybridHandler {
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"authorization_code", "implicit"},
					ResponseTypes: fosite.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				return makeOpenIDConnectHybridHandler(fosite.MinParameterEntropy)
			},
		},
		{
			description: "should pass because nonce was set with low entropy but also with low min entropy",
			setup: func() OpenIDConnectHybridHandler {
				areq.Form.Set("nonce", "short")
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"authorization_code", "implicit"},
					ResponseTypes: fosite.Arguments{"token", "code", "id_token"},
					Scopes:        []string{"openid"},
				}
				return makeOpenIDConnectHybridHandler(4)
			},
		},
		{
			description: "should pass because AuthorizeCode's ExpiresAt is set, even if AuthorizeCodeLifespan is zero",
			setup: func() OpenIDConnectHybridHandler {
				areq.Form.Set("nonce", "some-foobar-nonce-win")
				return makeOpenIDConnectHybridHandler(fosite.MinParameterEntropy)
			},
			check: func() {
				assert.True(t, !areq.Session.GetExpiresAt(fosite.AuthorizeCode).IsZero())
			},
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectHybridHandler {
				return makeOpenIDConnectHybridHandler(fosite.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get("id_token"))
				assert.NotEmpty(t, aresp.GetParameters().Get("code"))
				assert.NotEmpty(t, aresp.GetParameters().Get("access_token"))
				assert.Equal(t, time.Now().Add(time.Hour).UTC().Round(time.Second), areq.GetSession().GetExpiresAt(fosite.AuthorizeCode))
			},
		},
		{
			description: "Default responseMode check",
			setup: func() OpenIDConnectHybridHandler {
				return makeOpenIDConnectHybridHandler(fosite.MinParameterEntropy)
			},
			check: func() {
				assert.NotEmpty(t, aresp.GetParameters().Get("id_token"))
				assert.NotEmpty(t, aresp.GetParameters().Get("code"))
				assert.NotEmpty(t, aresp.GetParameters().Get("access_token"))
				assert.Equal(t, fosite.ResponseModeFragment, areq.GetResponseMode())
				assert.Equal(t, time.Now().Add(time.Hour).UTC().Round(time.Second), areq.GetSession().GetExpiresAt(fosite.AuthorizeCode))
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			h := c.setup()
			err := h.HandleAuthorizeEndpointRequest(nil, areq, aresp)

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}

			if c.check != nil {
				c.check()
			}
		})
	}
}
