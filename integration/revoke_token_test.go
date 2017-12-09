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

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/parnurzeal/gorequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goauth "golang.org/x/oauth2"
)

func TestRevokeToken(t *testing.T) {
	for _, strategy := range []oauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runRevokeTokenTest(t, strategy)
	}
}

func runRevokeTokenTest(t *testing.T, strategy oauth2.AccessTokenStrategy) {
	f := compose.Compose(new(compose.Config), fositeStore, strategy, nil, compose.OAuth2ClientCredentialsGrantFactory, compose.OAuth2TokenIntrospectionFactory, compose.OAuth2TokenRevocationFactory)
	ts := mockServer(t, f, &fosite.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2AppClient(ts)
	token, err := oauthClient.Token(goauth.NoContext)
	require.NoError(t, err)

	resp, _, errs := gorequest.New().Post(ts.URL+"/revoke").
		SetBasicAuth(oauthClient.ClientID, oauthClient.ClientSecret).
		Type("form").
		SendStruct(map[string]string{"token": "asdf"}).End()
	require.Len(t, errs, 0)
	assert.Equal(t, 200, resp.StatusCode)

	resp, _, errs = gorequest.New().Post(ts.URL+"/revoke").
		SetBasicAuth(oauthClient.ClientID, oauthClient.ClientSecret).
		Type("form").
		SendStruct(map[string]string{"token": token.AccessToken}).End()
	require.Len(t, errs, 0)
	assert.Equal(t, 200, resp.StatusCode)

	hres, _, errs := gorequest.New().Get(ts.URL+"/info").
		Set("Authorization", "bearer "+token.AccessToken).
		End()
	require.Len(t, errs, 0)
	assert.Equal(t, http.StatusUnauthorized, hres.StatusCode)
}
