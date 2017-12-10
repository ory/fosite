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
	"net/url"
	"strings"
	"testing"

	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseUrl(uu string) *url.URL {
	u, _ := url.Parse(uu)
	return u
}

func TestAuthorizeCode_HandleAuthorizeEndpointRequest(t *testing.T) {
	for k, strategy := range map[string]CoreStrategy{
		"hmac": &hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()
			h := AuthorizeExplicitGrantHandler{
				CoreStorage:           store,
				AuthorizeCodeStrategy: strategy,
				ScopeStrategy:         fosite.HierarchicScopeStrategy,
			}
			for _, c := range []struct {
				areq        *fosite.AuthorizeRequest
				description string
				expectErr   error
				expect      func(t *testing.T, areq *fosite.AuthorizeRequest, aresp *fosite.AuthorizeResponse)
			}{
				{
					areq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{""},
						Request:       *fosite.NewRequest(),
					},
					description: "should pass because not responsible for handling an empty response type",
				},
				{
					areq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{"foo"},
						Request:       *fosite.NewRequest(),
					},
					description: "should pass because not responsible for handling an invalid response type",
				},
				{
					areq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{"code"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ResponseTypes: fosite.Arguments{"code"},
								RedirectURIs:  []string{"http://asdf.com/cb"},
							},
						},
						RedirectURI: parseUrl("http://asdf.com/cb"),
					},
					description: "should fail because redirect uri is not https",
					expectErr:   fosite.ErrInvalidRequest,
				},
				{
					areq: &fosite.AuthorizeRequest{
						ResponseTypes: fosite.Arguments{"code"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ResponseTypes: fosite.Arguments{"code"},
								RedirectURIs:  []string{"https://asdf.de/cb"},
							},
							GrantedScopes: fosite.Arguments{"a", "b"},
							Session: &fosite.DefaultSession{
								ExpiresAt: map[fosite.TokenType]time.Time{fosite.AccessToken: time.Now().UTC().Add(time.Hour)},
							},
							RequestedAt: time.Now().UTC(),
						},
						State:       "superstate",
						RedirectURI: parseUrl("https://asdf.de/cb"),
					},
					description: "should pass",
					expect: func(t *testing.T, areq *fosite.AuthorizeRequest, aresp *fosite.AuthorizeResponse) {
						code := aresp.GetQuery().Get("code")
						assert.NotEmpty(t, code)

						assert.Equal(t, strings.Join(areq.GrantedScopes, " "), aresp.GetQuery().Get("scope"))
						assert.Equal(t, areq.State, aresp.GetQuery().Get("state"))
					},
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					aresp := fosite.NewAuthorizeResponse()
					err := h.HandleAuthorizeEndpointRequest(nil, c.areq, aresp)
					if c.expectErr != nil {
						require.EqualError(t, errors.Cause(err), c.expectErr.Error())
					} else {
						require.NoError(t, err)
					}

					if c.expect != nil {
						c.expect(t, c.areq, aresp)
					}
				})
			}
		})
	}
}
