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
	//"github.com/stretchr/testify/assert"
	"encoding/json"
	"net/url"

	"github.com/magiconair/properties/assert"
	"github.com/stretchr/testify/require"
	goauth "golang.org/x/oauth2"
)

func TestAuthorizeCodeFlowWithPublicClientAndPKCE(t *testing.T) {
	for _, strategy := range []oauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runAuthorizeCodeGrantWithPublicClientAndPKCETest(t, strategy)
	}
}

func runAuthorizeCodeGrantWithPublicClientAndPKCETest(t *testing.T, strategy interface{}) {
	c := new(compose.Config)
	c.EnforcePKCE = true
	c.EnablePKCEPlainChallengeMethod = true
	f := compose.Compose(c, fositeStore, strategy, nil, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2PKCEFactory, compose.OAuth2TokenIntrospectionFactory)
	ts := mockServer(t, f, &fosite.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	oauthClient.ClientSecret = ""
	oauthClient.ClientID = "public-client"
	fositeStore.Clients["public-client"].RedirectURIs[0] = ts.URL + "/callback"

	var authCodeUrl string
	var verifier string
	for k, c := range []struct {
		description    string
		setup          func()
		authStatusCode int
	}{
		{
			description: "should fail because no challenge was given",
			setup: func() {
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890")
			},
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			description: "should pass",
			setup: func() {
				verifier = "somechallenge"
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890") + "&code_challenge=somechallenge"
			},
			authStatusCode: http.StatusOK,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.setup()

			t.Logf("Got url: %s", authCodeUrl)

			resp, err := http.Get(authCodeUrl)
			require.NoError(t, err)
			require.Equal(t, c.authStatusCode, resp.StatusCode)

			if resp.StatusCode == http.StatusOK {
				// This should fail because no verifier was given
				_, err := oauthClient.Exchange(goauth.NoContext, resp.Request.URL.Query().Get("code"))
				require.Error(t, err)
				//require.Empty(t, token.AccessToken)

				resp, err := http.PostForm(ts.URL+"/token", url.Values{
					"code":          {resp.Request.URL.Query().Get("code")},
					"grant_type":    {"authorization_code"},
					"client_id":     {"public-client"},
					"redirect_uri":  {ts.URL + "/callback"},
					"code_verifier": {verifier},
				})
				require.NoError(t, err)
				defer resp.Body.Close()

				assert.Equal(t, resp.StatusCode, http.StatusOK)
				token := goauth.Token{}
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&token))

				httpClient := oauthClient.Client(goauth.NoContext, &token)
				resp, err = httpClient.Get(ts.URL + "/info")
				require.NoError(t, err)
				assert.Equal(t, http.StatusNoContent, resp.StatusCode)
			}
		})
	}
}
