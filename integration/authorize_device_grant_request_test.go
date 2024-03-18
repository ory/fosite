// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/ory/fosite/handler/rfc8628"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/internal/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goauth "golang.org/x/oauth2"
)

func TestDeviceFlow(t *testing.T) {
	runDeviceFlowTest(t)
	runDeviceFlowAccessTokenTest(t)
}

func runDeviceFlowTest(t *testing.T) {
	session := &rfc8628.DefaultDeviceFlowSession{}

	fc := &fosite.Config{
		DeviceVerificationURL: "https://example.com/",
		RefreshTokenLifespan:  -1,
		GlobalSecret:          []byte("some-secret-thats-random-some-secret-thats-random-"),
	}
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
		check       func(t *testing.T, token *goauth.DeviceAuthResponse, err error)
		cleanUp     func()
	}{
		{
			description: "should fail with invalid_grant",
			setup: func() {
				fositeStore.Clients["device-client"].(*fosite.DefaultClient).GrantTypes = []string{string(fosite.GrantTypeAuthorizationCode)}
			},
			err: true,
			check: func(t *testing.T, token *goauth.DeviceAuthResponse, err error) {
				assert.ErrorContains(t, err, "invalid_grant")
			},
			cleanUp: func() {
				fositeStore.Clients["device-client"].(*fosite.DefaultClient).GrantTypes = []string{string(fosite.GrantTypeDeviceCode)}
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
			cleanUp: func() {
				oauthClient.Scopes = []string{}
				fositeStore.Clients["device-client"].(*fosite.DefaultClient).Scopes = []string{"fosite", "offline", "openid"}
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
			cleanUp: func() {
				oauthClient.ClientID = "device-client"
			},
		},
		{
			description: "should pass",
			setup:       func() {},
			err:         false,
		},
	} {
		t.Run(fmt.Sprintf("case=%d description=%s", k, c.description), func(t *testing.T) {
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

			if c.cleanUp != nil {
				c.cleanUp()
			}

			t.Logf("Passed test case %d", k)
		})
	}
}

func runDeviceFlowAccessTokenTest(t *testing.T) {
	session := &rfc8628.DefaultDeviceFlowSession{
		BrowserFlowCompleted: true,
	}

	fc := &fosite.Config{
		DeviceVerificationURL:          "https://example.com/",
		RefreshTokenLifespan:           -1,
		GlobalSecret:                   []byte("some-secret-thats-random-some-secret-thats-random-"),
		DeviceAuthTokenPollingInterval: -1,
	}
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
	resp, _ := oauthClient.DeviceAuth(context.Background())

	for k, c := range []struct {
		description string
		setup       func()
		params      []goauth.AuthCodeOption
		err         bool
		check       func(t *testing.T, token *goauth.Token, err error)
		cleanUp     func()
	}{
		{
			description: "should fail with invalid grant type",
			setup: func() {
			},
			params: []goauth.AuthCodeOption{goauth.SetAuthURLParam("grant_type", "invalid_grant_type")},
			err:    true,
			check: func(t *testing.T, token *goauth.Token, err error) {
				assert.ErrorContains(t, err, "invalid_request")
			},
		},
		{
			description: "should fail with unauthorized client",
			setup: func() {
				fositeStore.Clients["device-client"].(*fosite.DefaultClient).GrantTypes = []string{string(fosite.GrantTypeAuthorizationCode)}
			},
			params: []goauth.AuthCodeOption{},
			err:    true,
			check: func(t *testing.T, token *goauth.Token, err error) {
				assert.ErrorContains(t, err, "unauthorized_client")
			},
			cleanUp: func() {
				fositeStore.Clients["device-client"].(*fosite.DefaultClient).GrantTypes = []string{string(fosite.GrantTypeDeviceCode)}
			},
		},
		{
			description: "should fail with invalid device code",
			setup:       func() {},
			params:      []goauth.AuthCodeOption{goauth.SetAuthURLParam("device_code", "invalid_device_code")},
			err:         true,
			check: func(t *testing.T, token *goauth.Token, err error) {
				assert.ErrorContains(t, err, "invalid_grant")
			},
		},
		{
			description: "should fail with invalid client id",
			setup: func() {
				oauthClient.ClientID = "invalid_client_id"
			},
			err: true,
			check: func(t *testing.T, token *goauth.Token, err error) {
				assert.ErrorContains(t, err, "invalid_client")
			},
			cleanUp: func() {
				oauthClient.ClientID = "device-client"
			},
		},
		{
			description: "should pass",
			setup:       func() {},
			err:         false,
		},
	} {
		t.Run(fmt.Sprintf("case=%d description=%s", k, c.description), func(t *testing.T) {
			c.setup()

			token, err := oauthClient.DeviceAccessToken(context.Background(), resp, c.params...)
			if !c.err {
				assert.NotEmpty(t, token.AccessToken)
			}

			if c.check != nil {
				c.check(t, token, err)
			}

			if c.cleanUp != nil {
				c.cleanUp()
			}

			t.Logf("Passed test case %d", k)
		})
	}
}
