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

package integration_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/magiconair/properties/assert"
	"github.com/stretchr/testify/require"
	goauth "golang.org/x/oauth2"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2" // "github.com/stretchr/testify/assert"
)

func TestAuthorizeCodeFlowWithPKCE(t *testing.T) {
	for _, strategy := range []oauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runAuthorizeCodeGrantWithPKCETest(t, strategy)
	}
}

func runAuthorizeCodeGrantWithPKCETest(t *testing.T, strategy interface{}) {
	var oauthClient *goauth.Config
	var authCodeUrl string
	var verifier string

	// create a test server with DisablePKCEForConfidentialClients = false (by default)
	cfg := new(compose.Config)
	cfg.EnforcePKCE = true
	cfg.EnablePKCEPlainChallengeMethod = true
	testserverWithEnforcePKCE := mockServer(
		t,
		compose.Compose(cfg, fositeStore, strategy, nil, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2PKCEFactory, compose.OAuth2TokenIntrospectionFactory),
		&fosite.DefaultSession{},
	)
	defer testserverWithEnforcePKCE.Close()

	// create a test server with DisablePKCEForConfidentialClients = true
	cfgConfidentialDisabled := new(compose.Config)
	cfgConfidentialDisabled.EnforcePKCE = true
	cfgConfidentialDisabled.EnablePKCEPlainChallengeMethod = true
	cfgConfidentialDisabled.DisablePKCEForConfidentialClients = true
	testserverWithEnforcePKCEForPublicClientsOnly := mockServer(
		t,
		compose.Compose(cfgConfidentialDisabled, fositeStore, strategy, nil, compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2PKCEFactory, compose.OAuth2TokenIntrospectionFactory),
		&fosite.DefaultSession{},
	)
	defer testserverWithEnforcePKCEForPublicClientsOnly.Close()

	for k, c := range []struct {
		description     string
		clientID        string
		clientSecret    string
		testserver      *httptest.Server
		setup           func(testserver *httptest.Server, clientID string, clientSecret string)
		authStatusCode  int
		tokenStatusCode int
	}{
		{
			description:  "PKCE disabled public client: should fail because no challenge was given",
			clientID:     "public-client",
			clientSecret: "",
			setup: func(testserver *httptest.Server, clientID string, clientSecret string) {
				oauthClient = newTestOAuthClient(testserver, clientID, clientSecret)
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890")
			},
			testserver:     testserverWithEnforcePKCE,
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			description:  "PKCE enabled public client: should pass",
			clientID:     "public-client",
			clientSecret: "",
			testserver:   testserverWithEnforcePKCE,
			setup: func(testserver *httptest.Server, clientID string, clientSecret string) {
				oauthClient = newTestOAuthClient(testserver, clientID, clientSecret)
				verifier = "somechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890") + "&code_challenge=somechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
			},
			authStatusCode: http.StatusOK,
		},
		{
			description:  "PKCE enabled public client: should fail because the verifier is mismatching",
			clientID:     "public-client",
			clientSecret: "",
			testserver:   testserverWithEnforcePKCE,
			setup: func(testserver *httptest.Server, clientID string, clientSecret string) {
				oauthClient = newTestOAuthClient(testserver, clientID, clientSecret)
				verifier = "failchallengefailchallengefailchallengefailchallengefailchallengefailchallengefailchallengefailchallenge"
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890") + "&code_challenge=somechallengesomechallengesomechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
			},
			authStatusCode:  http.StatusOK,
			tokenStatusCode: http.StatusBadRequest,
		},
		{
			description:  "PKCE disabled confidential client: should fail because no challenge was given",
			clientID:     "my-client",
			clientSecret: "foobar",
			testserver:   testserverWithEnforcePKCE,
			setup: func(testserver *httptest.Server, clientID string, clientSecret string) {
				oauthClient = newTestOAuthClient(testserver, clientID, clientSecret)
				verifier = ""
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890")
			},
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			description:  "PKCE enabled confidential client: should pass",
			clientID:     "my-client",
			clientSecret: "foobar",
			testserver:   testserverWithEnforcePKCE,
			setup: func(testserver *httptest.Server, clientID string, clientSecret string) {
				oauthClient = newTestOAuthClient(testserver, clientID, clientSecret)
				verifier = "somechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890") + "&code_challenge=somechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
			},
			authStatusCode: http.StatusOK,
		},
		{
			description:  "PKCE enabled confidential client: should fail because the verifier is mismatching",
			clientID:     "my-client",
			clientSecret: "foobar",
			testserver:   testserverWithEnforcePKCE,
			setup: func(testserver *httptest.Server, clientID string, clientSecret string) {
				oauthClient = newTestOAuthClient(testserver, clientID, clientSecret)
				verifier = "failchallengefailchallengefailchallengefailchallengefailchallengefailchallengefailchallengefailchallenge"
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890") + "&code_challenge=somechallengesomechallengesomechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
			},
			authStatusCode:  http.StatusOK,
			tokenStatusCode: http.StatusBadRequest,
		},
		{
			description:  "PKCE disabled confidential client: should pass",
			clientID:     "my-client",
			clientSecret: "foobar",
			testserver:   testserverWithEnforcePKCEForPublicClientsOnly,
			setup: func(testserver *httptest.Server, clientID string, clientSecret string) {
				oauthClient = newTestOAuthClient(testserver, clientID, clientSecret)
				verifier = ""
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890")
			},
			authStatusCode: http.StatusOK,
		},
		{
			description:  "PKCE enabled confidential client: should fail because PKCE is disabled for confidential clients",
			clientID:     "my-client",
			clientSecret: "foobar",
			testserver:   testserverWithEnforcePKCEForPublicClientsOnly,
			setup: func(testserver *httptest.Server, clientID string, clientSecret string) {
				oauthClient = newTestOAuthClient(testserver, clientID, clientSecret)
				verifier = "failchallengefailchallengefailchallengefailchallengefailchallengefailchallengefailchallengefailchallenge"
				authCodeUrl = oauthClient.AuthCodeURL("12345678901234567890") + "&code_challenge=somechallengesomechallengesomechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
			},
			authStatusCode: http.StatusNotAcceptable,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.setup(c.testserver, c.clientID, c.clientSecret)
			fositeStore.Clients[c.clientID].(*fosite.DefaultClient).RedirectURIs[0] = c.testserver.URL + "/callback"

			t.Logf("Got url: %s", authCodeUrl)

			resp, err := http.Get(authCodeUrl)
			require.NoError(t, err)
			require.Equal(t, resp.StatusCode, c.authStatusCode)

			if resp.StatusCode == http.StatusOK {
				// This should fail because no verifier was given
				// _, err := oauthClient.Exchange(goauth.NoContext, resp.Request.URL.Query().Get("code"))
				// require.Error(t, err)
				// require.Empty(t, token.AccessToken)
				t.Logf("Got redirect url: %s", resp.Request.URL)

				client := &http.Client{}
				data := url.Values{
					"code":         {resp.Request.URL.Query().Get("code")},
					"grant_type":   {"authorization_code"},
					"client_id":    {c.clientID},
					"redirect_uri": {c.testserver.URL + "/callback"},
				}
				if verifier != "" {
					data.Add("code_verifier", verifier)
				}
				req, _ := http.NewRequest(
					"POST",
					c.testserver.URL+"/token",
					strings.NewReader(data.Encode()),
				)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if c.clientSecret != "" {
					req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.clientID+":"+c.clientSecret)))
				}
				resp, err := client.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()

				body, err := ioutil.ReadAll(resp.Body)
				require.NoError(t, err)

				if c.tokenStatusCode != 0 {
					require.Equal(t, c.tokenStatusCode, resp.StatusCode)
					token := goauth.Token{}
					require.NoError(t, json.Unmarshal(body, &token))
					require.Empty(t, token.AccessToken)
					return
				}

				assert.Equal(t, resp.StatusCode, http.StatusOK)
				token := goauth.Token{}
				require.NoError(t, json.Unmarshal(body, &token))

				require.NotEmpty(t, token.AccessToken, "Got body: %s", string(body))

				httpClient := oauthClient.Client(goauth.NoContext, &token)
				resp, err = httpClient.Get(c.testserver.URL + "/info")
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
			}
		})
	}
}

func newTestOAuthClient(ts *httptest.Server, clientID string, clientSecret string) *goauth.Config {
	oauthClient := newOAuth2Client(ts)
	oauthClient.ClientSecret = clientSecret
	oauthClient.ClientID = clientID
	return oauthClient
}
