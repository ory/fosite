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
	"net/http"
	"testing"
	"time"

	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestRefreshTokenFlow(t *testing.T) {
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
	state := "1234567890"
	fositeStore.Clients["my-client"].RedirectURIs[0] = ts.URL + "/callback"
	for _, c := range []struct {
		description string
		setup       func()
		pass        bool
		check       func(original, refreshed *oauth2.Token)
	}{
		{
			description: "should fail because refresh scope missing",
			setup: func() {
				oauthClient.Scopes = []string{"fosite"}
			},
			pass: false,
		},
		{
			description: "should pass but not yield id token",
			setup: func() {
				oauthClient.Scopes = []string{"offline"}
			},
			pass: true,
			check: func(original, refreshed *oauth2.Token) {
				assert.NotEqual(t, original.RefreshToken, refreshed.RefreshToken)
				assert.NotEqual(t, original.AccessToken, refreshed.AccessToken)
				assert.Nil(t, refreshed.Extra("id_token"))
			},
		},
		{
			description: "should pass and yield id token",
			setup: func() {
				oauthClient.Scopes = []string{"fosite", "offline", "openid"}
			},
			pass: true,
			check: func(original, refreshed *oauth2.Token) {
				assert.NotEqual(t, original.RefreshToken, refreshed.RefreshToken)
				assert.NotEqual(t, original.AccessToken, refreshed.AccessToken)
				assert.NotNil(t, refreshed.Extra("id_token"))
			},
		},
	} {
		t.Run("case="+c.description, func(t *testing.T) {
			c.setup()

			resp, err := http.Get(oauthClient.AuthCodeURL(state))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			if resp.StatusCode != http.StatusOK {
				return
			}

			token, err := oauthClient.Exchange(oauth2.NoContext, resp.Request.URL.Query().Get("code"))
			require.NoError(t, err)
			require.NotEmpty(t, token.AccessToken)

			t.Logf("Token %s\n", token)
			token.Expiry = token.Expiry.Add(-time.Hour * 24)

			tokenSource := oauthClient.TokenSource(oauth2.NoContext, token)
			refreshed, err := tokenSource.Token()
			if c.pass {
				require.NoError(t, err)
				c.check(token, refreshed)
			} else {
				require.Error(t, err)
			}
		})
	}
}
