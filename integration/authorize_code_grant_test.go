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

package integration_test

import (
	"testing"

	"net/http"

	"fmt"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goauth "golang.org/x/oauth2"
)

func TestAuthorizeCodeFlow(t *testing.T) {
	for _, strategy := range []oauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runAuthorizeCodeGrantTest(t, strategy)
	}
}

func runAuthorizeCodeGrantTest(t *testing.T, strategy interface{}) {
	f := compose.Compose(new(compose.Config), fositeStore, strategy, nil, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2TokenIntrospectionFactory)
	ts := mockServer(t, f, &fosite.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	fositeStore.Clients["my-client"].RedirectURIs[0] = ts.URL + "/callback"

	var state string
	for k, c := range []struct {
		description    string
		setup          func()
		authStatusCode int
	}{
		{
			description: "should pass",
			setup: func() {
				oauthClient = newOAuth2Client(ts)
				state = "12345678901234567890"
			},
			authStatusCode: http.StatusOK,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.setup()

			resp, err := http.Get(oauthClient.AuthCodeURL(state))
			require.NoError(t, err)
			require.Equal(t, c.authStatusCode, resp.StatusCode)

			if resp.StatusCode == http.StatusOK {
				token, err := oauthClient.Exchange(goauth.NoContext, resp.Request.URL.Query().Get("code"))
				require.NoError(t, err)
				require.NotEmpty(t, token.AccessToken)

				httpClient := oauthClient.Client(goauth.NoContext, token)
				resp, err := httpClient.Get(ts.URL + "/info")
				require.NoError(t, err)
				assert.Equal(t, http.StatusNoContent, resp.StatusCode)
			}
		})
	}
}
