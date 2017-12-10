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

	"fmt"

	"io/ioutil"
	"strings"
	"time"

	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func newIDSession(j *jwt.IDTokenClaims) *defaultSession {
	return &defaultSession{
		DefaultSession: &openid.DefaultSession{
			Claims:  j,
			Headers: &jwt.Headers{},
		},
	}
}

func TestOpenIDConnectExplicitFlow(t *testing.T) {
	f := compose.ComposeAllEnabled(new(compose.Config), fositeStore, []byte("some-secret-thats-random-some-secret-thats-random-"), internal.MustRSAKey())

	for k, c := range []struct {
		description    string
		setup          func(oauthClient *oauth2.Config) string
		authStatusCode int
		authCodeURL    string
		session        *defaultSession
		expectAuthErr  string
		expectTokenErr string
	}{
		{
			session:     newIDSession(&jwt.IDTokenClaims{Subject: "peter"}),
			description: "should pass",
			setup: func(oauthClient *oauth2.Config) string {
				oauthClient.Scopes = []string{"openid"}
				return oauthClient.AuthCodeURL("12345678901234567890") + "&nonce=11234123"
			},
			authStatusCode: http.StatusOK,
		},
		{
			session:     newIDSession(&jwt.IDTokenClaims{Subject: "peter"}),
			description: "should fail because nonce is not long enough",
			setup: func(oauthClient *oauth2.Config) string {
				oauthClient.Scopes = []string{"openid"}
				return oauthClient.AuthCodeURL("12345678901234567890") + "&nonce=1"
			},
			authStatusCode: http.StatusOK,
			expectTokenErr: "insufficient_entropy",
		},
		{
			session:     newIDSession(&jwt.IDTokenClaims{Subject: "peter"}),
			description: "should fail because state is not long enough",
			setup: func(oauthClient *oauth2.Config) string {
				oauthClient.Scopes = []string{"openid"}
				return oauthClient.AuthCodeURL("123") + "&nonce=1234567890"
			},
			expectAuthErr:  "invalid_state",
			authStatusCode: http.StatusNotAcceptable, // code from internal test callback handler when error occurs
		},
		{
			session: newIDSession(&jwt.IDTokenClaims{
				Subject:     "peter",
				RequestedAt: time.Now().UTC(),
				AuthTime:    time.Now().Add(time.Second).UTC(),
			}),
			description: "should pass",
			setup: func(oauthClient *oauth2.Config) string {
				oauthClient.Scopes = []string{"openid"}
				return oauthClient.AuthCodeURL("12345678901234567890") + "&nonce=1234567890&prompt=login"
			},
			authStatusCode: http.StatusOK,
		},
		{
			session: newIDSession(&jwt.IDTokenClaims{
				Subject:     "peter",
				RequestedAt: time.Now().UTC(),
				AuthTime:    time.Now().Add(-time.Minute).UTC(),
			}),
			description: "should fail because authentication was in the past",
			setup: func(oauthClient *oauth2.Config) string {
				oauthClient.Scopes = []string{"openid"}
				return oauthClient.AuthCodeURL("12345678901234567890") + "&nonce=1234567890&prompt=login"
			},
			authStatusCode: http.StatusOK,
			expectTokenErr: "login_required",
		},
		{
			session: newIDSession(&jwt.IDTokenClaims{
				Subject:     "peter",
				RequestedAt: time.Now().UTC(),
				AuthTime:    time.Now().Add(-time.Minute).UTC(),
			}),
			description: "should pass because authorization was in the past and no login was required",
			setup: func(oauthClient *oauth2.Config) string {
				oauthClient.Scopes = []string{"openid"}
				return oauthClient.AuthCodeURL("12345678901234567890") + "&nonce=1234567890&prompt=none"
			},
			authStatusCode: http.StatusOK,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			ts := mockServer(t, f, c.session)
			defer ts.Close()

			oauthClient := newOAuth2Client(ts)
			fositeStore.Clients["my-client"].RedirectURIs[0] = ts.URL + "/callback"

			resp, err := http.Get(c.setup(oauthClient))
			require.NoError(t, err)
			defer resp.Body.Close()

			body, _ := ioutil.ReadAll(resp.Body)
			require.Equal(t, c.authStatusCode, resp.StatusCode, "Got response: %s", body)
			if resp.StatusCode >= 400 {
				assert.Equal(t, c.expectAuthErr, strings.Replace(string(body), "error: ", "", 1))
			}

			if c.expectAuthErr != "" {
				assert.Empty(t, resp.Request.URL.Query().Get("code"))
			}

			if resp.StatusCode == http.StatusOK {
				time.Sleep(time.Second)

				token, err := oauthClient.Exchange(oauth2.NoContext, resp.Request.URL.Query().Get("code"))

				if c.expectTokenErr != "" {
					assert.Error(t, err)
					assert.True(t, strings.Contains(err.Error(), c.expectTokenErr), err.Error())
				} else {
					require.NoError(t, err)
					assert.NotEmpty(t, token.AccessToken)
					assert.NotEmpty(t, token.Extra("id_token"))
				}
			}
		})
	}
}
