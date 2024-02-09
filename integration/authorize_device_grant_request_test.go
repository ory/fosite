// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/internal/gen"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goauth "golang.org/x/oauth2"
)

func TestDeviceFlow(t *testing.T) {
	for _, strategy := range []oauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runDeviceFlowTest(t, strategy)
	}
}

func runDeviceFlowTest(t *testing.T, strategy interface{}) {
	session := &defaultSession{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject: "peter",
			},
			Headers:  &jwt.Headers{},
			Subject:  "peter",
			Username: "peteru",
		},
	}
	fc := new(fosite.Config)
	fc.DeviceVerificationURL = "https://example.com/"
	fc.RefreshTokenLifespan = -1
	fc.GlobalSecret = []byte("some-secret-thats-random-some-secret-thats-random-")
	f := compose.ComposeAllEnabled(fc, fositeStore, gen.MustRSAKey())
	ts := mockServer(t, f, session)
	defer ts.Close()

	oauthClient := &goauth.Config{
		ClientID:     "device-client",
		ClientSecret: "foobar",
		Endpoint: goauth.Endpoint{
			TokenURL:      ts.URL + tokenRelativePath,
			DeviceAuthURL: ts.URL + deviceAuthRelativePath,
		},
	}
	for k, c := range []struct {
		description string
		setup       func()
		err         bool
		client      fosite.Client
		check       func(t *testing.T, token *goauth.DeviceAuthResponse, err error)
		params      url.Values
	}{
		{
			description: "should fail with invalid_grant",
			setup: func() {
				fositeStore.Clients["device-client"].(*fosite.DefaultClient).GrantTypes = []string{"authorization_code"}
			},
			err: true,
			check: func(t *testing.T, token *goauth.DeviceAuthResponse, err error) {
				assert.ErrorContains(t, err, "invalid_grant")
			},
		},
		{
			description: "should fail with invalid_scope",
			setup: func() {
				oauthClient.Scopes = []string{"openid"}
				fositeStore.Clients["device-client"].(*fosite.DefaultClient).Scopes = []string{"profile"}
			},
			err: true,
			check: func(t *testing.T, token *goauth.DeviceAuthResponse, err error) {
				assert.ErrorContains(t, err, "invalid_scope")
			},
		},
		{
			description: "should fail with invalid_client",
			setup: func() {
				oauthClient.ClientID = "123"
			},
			err: true,
			check: func(t *testing.T, token *goauth.DeviceAuthResponse, err error) {
				assert.ErrorContains(t, err, "invalid_client")
			},
		},
		{
			description: "should pass",
			setup:       func() {},
			err:         false,
		},
	} {
		t.Run(fmt.Sprintf("case=%d description=%s", k, c.description), func(t *testing.T) {
			// Restore client
			fositeStore.Clients["device-client"] = &fosite.DefaultClient{
				ID:         "device-client",
				Secret:     []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
				GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
				Scopes:     []string{"fosite", "offline", "openid"},
				Audience:   []string{tokenURL},
				Public:     true,
			}
			oauthClient = &goauth.Config{
				ClientID:     "device-client",
				ClientSecret: "foobar",
				Endpoint: goauth.Endpoint{
					TokenURL:      ts.URL + tokenRelativePath,
					DeviceAuthURL: ts.URL + deviceAuthRelativePath,
				},
			}

			c.setup()

			resp, err := oauthClient.DeviceAuth(context.Background())
			require.Equal(t, c.err, err != nil, "(%d) %s\n%s\n%s", k, c.description, c.err, err)
			if !c.err {
				assert.NotEmpty(t, resp.DeviceCode)
				assert.NotEmpty(t, resp.UserCode)
				assert.NotEmpty(t, resp.Interval)
				assert.NotEmpty(t, resp.VerificationURI)
				assert.NotEmpty(t, resp.VerificationURIComplete)
			}

			if c.check != nil {
				c.check(t, resp, err)
			}

			t.Logf("Passed test case %d", k)
		})
	}
}
