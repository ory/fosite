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
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/token/jwt"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goauth "golang.org/x/oauth2"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
)

func TestAuthorizeFormPostImplicitFlow(t *testing.T) {
	for _, strategy := range []oauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runTestAuthorizeFormPostImplicitGrant(t, strategy)
	}
}

func runTestAuthorizeFormPostImplicitGrant(t *testing.T, strategy interface{}) {
	session := &defaultSession{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject: "peter",
			},
			Headers: &jwt.Headers{},
		},
	}
	f := compose.ComposeAllEnabled(new(compose.Config), fositeStore, []byte("some-secret-thats-random-some-secret-thats-random-"), internal.MustRSAKey())
	ts := mockServer(t, f, session)
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	fositeStore.Clients["my-client"].(*fosite.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

	var state string
	for k, c := range []struct {
		description  string
		setup        func()
		check        func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, err fosite.RFC6749Error)
		responseType string
	}{
		//{
		//	description: "should fail because of audience",
		//	responseType:      []goauth.AuthCodeOption{goauth.SetAuthURLParam("audience", "https://www.ory.sh/not-api")},
		//	setup: func() {
		//		state = "12345678901234567890"
		//	},
		//	authStatusCode: http.StatusNotAcceptable,
		//},
		//{
		//	description: "should fail because of scope",
		//	responseType:      []goauth.AuthCodeOption{},
		//	setup: func() {
		//		oauthClient.Scopes = []string{"not-exist"}
		//		state = "12345678901234567890"
		//	},
		//	authStatusCode: http.StatusNotAcceptable,
		//},
		{
			description:  "implicit grant test with form_post",
			responseType: "token",
			setup: func() {
				state = "12345678901234567890"
			},
			check: func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, err fosite.RFC6749Error) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, token.TokenType)
				assert.NotEmpty(t, token.AccessToken)
				assert.NotEmpty(t, token.Expiry)
			},
		},
		{
			description:  "explicit grant test with form_post",
			responseType: "code",
			setup: func() {
				state = "12345678901234567890"
			},
			check: func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, err fosite.RFC6749Error) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, code)
			},
		},
		{
			description:  "oidc grant test with form_post",
			responseType: "token%20code",
			setup: func() {
				state = "12345678901234567890"
				oauthClient.Scopes = []string{"openid"}
			},
			check: func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, err fosite.RFC6749Error) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, code)
				assert.NotEmpty(t, token.TokenType)
				assert.NotEmpty(t, token.AccessToken)
				assert.NotEmpty(t, token.Expiry)
			},
		},
		{
			description:  "hybrid grant test with form_post",
			responseType: "token%20id_token%20code",
			setup: func() {
				state = "12345678901234567890"
				oauthClient.Scopes = []string{"openid"}
			},
			check: func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, err fosite.RFC6749Error) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, code)
				assert.NotEmpty(t, iDToken)
				assert.NotEmpty(t, token.TokenType)
				assert.NotEmpty(t, token.AccessToken)
				assert.NotEmpty(t, token.Expiry)
			},
		},
		{
			description:  "hybrid grant test with form_post",
			responseType: "id_token%20code",
			setup: func() {
				state = "12345678901234567890"
				oauthClient.Scopes = []string{"openid"}
			},
			check: func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, err fosite.RFC6749Error) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, code)
				assert.NotEmpty(t, iDToken)
			},
		},
		{
			description:  "error message test for form_post response",
			responseType: "foo",
			setup: func() {
				state = "12345678901234567890"
			},
			check: func(t *testing.T, stateFromServer string, code string, token goauth.Token, iDToken string, err fosite.RFC6749Error) {
				assert.EqualValues(t, state, stateFromServer)
				assert.NotEmpty(t, err.Name)
				assert.NotEmpty(t, err.Description)
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.setup()
			authURL := strings.Replace(oauthClient.AuthCodeURL(state, goauth.SetAuthURLParam("response_mode", "form_post"), goauth.SetAuthURLParam("nonce", "111111111")), "response_type=code", "response_type="+c.responseType, -1)
			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return errors.New("Dont follow redirects")
				},
			}
			resp, err := client.Get(authURL)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			code, state, token, iDToken, errResp, err := fosite.ParseFormPostResponse(fositeStore.Clients["my-client"].GetRedirectURIs()[0], resp.Body)
			require.NoError(t, err)
			c.check(t, state, code, iDToken, token, errResp)
		})
	}
}
