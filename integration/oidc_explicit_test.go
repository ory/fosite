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

	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestOpenIDConnectExplicitFlow(t *testing.T) {
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
				state = "12345678901234567890"
				oauthClient.Scopes = []string{"openid"}
			},
			authStatusCode: http.StatusOK,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.setup()

			resp, err := http.Get(oauthClient.AuthCodeURL(state) + "&nonce=1234567890")
			require.NoError(t, err)
			require.Equal(t, c.authStatusCode, resp.StatusCode)

			if resp.StatusCode == http.StatusOK {
				token, err := oauthClient.Exchange(oauth2.NoContext, resp.Request.URL.Query().Get("code"))
				fmt.Printf("after exchange: %s\n\n", fositeStore.AuthorizeCodes)
				require.NoError(t, err)
				require.NotEmpty(t, token.AccessToken)
				require.NotEmpty(t, token.Extra("id_token"))
			}
		})
	}
}
