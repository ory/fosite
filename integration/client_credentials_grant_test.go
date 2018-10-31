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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goauth "golang.org/x/oauth2"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
)

func TestClientCredentialsFlow(t *testing.T) {
	for _, strategy := range []oauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runClientCredentialsGrantTest(t, strategy)
	}
}

func runClientCredentialsGrantTest(t *testing.T, strategy oauth2.AccessTokenStrategy) {
	f := compose.Compose(new(compose.Config), fositeStore, strategy, nil, compose.OAuth2ClientCredentialsGrantFactory, compose.OAuth2TokenIntrospectionFactory)
	ts := mockServer(t, f, &fosite.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2AppClient(ts)
	for k, c := range []struct {
		description string
		setup       func()
		err         bool
		check       func(t *testing.T, r *http.Response)
		params      url.Values
	}{
		{
			description: "should fail because of ungranted scopes",
			setup: func() {
				oauthClient.Scopes = []string{"unknown"}
			},
			err: true,
		},
		{
			description: "should fail because of ungranted audience",
			params:      url.Values{"audience": {"https://www.ory.sh/not-api"}},
			setup: func() {
				oauthClient.Scopes = []string{"fosite"}
			},
			err: true,
		},
		{
			params:      url.Values{"audience": {"https://www.ory.sh/api"}},
			description: "should pass",
			setup: func() {
			},
			check: func(t *testing.T, r *http.Response) {
				var b fosite.AccessRequest
				b.Client = new(fosite.DefaultClient)
				b.Session = new(defaultSession)
				require.NoError(t, json.NewDecoder(r.Body).Decode(&b))
				assert.EqualValues(t, fosite.Arguments{"https://www.ory.sh/api"}, b.RequestedAudience)
				assert.EqualValues(t, fosite.Arguments{"https://www.ory.sh/api"}, b.GrantedAudience)
				assert.EqualValues(t, "my-client", b.Session.(*defaultSession).Subject)
			},
		},
		{
			description: "should pass",
			setup: func() {
			},
			check: func(t *testing.T, r *http.Response) {
				var b fosite.AccessRequest
				b.Client = new(fosite.DefaultClient)
				b.Session = new(defaultSession)
				require.NoError(t, json.NewDecoder(r.Body).Decode(&b))
				assert.EqualValues(t, fosite.Arguments{}, b.RequestedAudience)
				assert.EqualValues(t, fosite.Arguments{}, b.GrantedAudience)
				assert.EqualValues(t, "my-client", b.Session.(*defaultSession).Subject)
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()

			oauthClient.EndpointParams = c.params
			token, err := oauthClient.Token(goauth.NoContext)
			require.Equal(t, c.err, err != nil, "(%d) %s\n%s\n%s", k, c.description, c.err, err)
			if !c.err {
				assert.NotEmpty(t, token.AccessToken, "(%d) %s\n%s", k, c.description, token)
			}
			t.Logf("Passed test case %d", k)
		})
	}
}
