// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/ory/fosite"
	"github.com/ory/fosite/internal"
)

func TestNewDeviceRequestWithPublicClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	client := &DefaultClient{ID: "client_id"}
	defer ctrl.Finish()
	config := &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}
	fosite := &Fosite{Store: store, Config: config}
	for k, c := range []struct {
		header        http.Header
		form          url.Values
		method        string
		expectedError error
		mock          func()
		expect        DeviceRequester
		description   string
	}{{
		description:   "invalid method",
		expectedError: ErrInvalidRequest,
		method:        "GET",
		mock:          func() {},
	}, {
		description:   "empty request",
		expectedError: ErrInvalidRequest,
		method:        "POST",
		mock:          func() {},
	}, {
		description: "invalid client",
		form: url.Values{
			"client_id": {"client_id"},
			"scope":     {"foo bar"},
		},
		expectedError: ErrInvalidClient,
		method:        "POST",
		mock: func() {
			store.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(nil, errors.New(""))
		},
	}, {
		description: "fails because scope not allowed",
		form: url.Values{
			"client_id": {"client_id"},
			"scope":     {"17 42 foo"},
		},
		method: "POST",
		mock: func() {
			store.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(client, nil)
			client.Public = true
			client.Scopes = []string{"17", "42"}
			client.GrantTypes = []string{"urn:ietf:params:oauth:grant-type:device_code"}
		},
		expectedError: ErrInvalidScope,
	}, {
		description: "fails because audience not allowed",
		form: url.Values{
			"client_id": {"client_id"},
			"scope":     {"17 42"},
			"audience":  {"aud"},
		},
		method: "POST",
		mock: func() {
			store.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(client, nil)
			client.Public = true
			client.Scopes = []string{"17", "42"}
			client.Audience = []string{"aud2"}
			client.GrantTypes = []string{"urn:ietf:params:oauth:grant-type:device_code"}
		},
		expectedError: ErrInvalidRequest,
	}, {
		description: "fails because it doesn't have the proper grant",
		form: url.Values{
			"client_id": {"client_id"},
			"scope":     {"17 42"},
		},
		method: "POST",
		mock: func() {
			store.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(client, nil)
			client.Public = true
			client.Scopes = []string{"17", "42"}
			client.GrantTypes = []string{"authorization_code"}
		},
		expectedError: ErrInvalidGrant,
	}, {
		description: "success",
		form: url.Values{
			"client_id": {"client_id"},
			"scope":     {"17 42"},
		},
		method: "POST",
		mock: func() {
			store.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(client, nil)
			client.Public = true
			client.Scopes = []string{"17", "42"}
			client.GrantTypes = []string{"urn:ietf:params:oauth:grant-type:device_code"}
		},
	}} {
		t.Run(fmt.Sprintf("case=%d description=%s", k, c.description), func(t *testing.T) {
			c.mock()
			r := &http.Request{
				Header:   c.header,
				PostForm: c.form,
				Form:     c.form,
				Method:   c.method,
			}

			ar, err := fosite.NewDeviceRequest(context.Background(), r)
			if c.expectedError != nil {
				assert.EqualError(t, err, c.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}

func TestNewDeviceRequestWithClientAuthn(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	hasher := internal.NewMockHasher(ctrl)
	client := &DefaultClient{ID: "client_id"}
	defer ctrl.Finish()
	config := &Config{ClientSecretsHasher: hasher, ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}
	fosite := &Fosite{Store: store, Config: config}
	for k, c := range []struct {
		header        http.Header
		form          url.Values
		method        string
		expectedError error
		mock          func()
		expect        DeviceRequester
	}{
		// No client authn provided
		{
			form: url.Values{
				"client_id": {"client_id"},
				"scope":     {"foo bar"},
			},
			expectedError: ErrInvalidClient,
			method:        "POST",
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(client, nil)
				client.Public = false
				client.Secret = []byte("client_secret")
				client.Scopes = []string{"foo", "bar"}
				client.GrantTypes = []string{"urn:ietf:params:oauth:grant-type:device_code"}
				hasher.EXPECT().Compare(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New(""))
			},
		},
		// success
		{
			form: url.Values{
				"client_id": {"client_id"},
				"scope":     {"foo bar"},
			},
			header: http.Header{
				"Authorization": {basicAuth("client_id", "client_secret")},
			},
			method: "POST",
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(client, nil)
				client.Public = false
				client.Secret = []byte("client_secret")
				client.Scopes = []string{"foo", "bar"}
				client.GrantTypes = []string{"urn:ietf:params:oauth:grant-type:device_code"}
				hasher.EXPECT().Compare(gomock.Any(), gomock.Eq([]byte("client_secret")), gomock.Eq([]byte("client_secret"))).Return(nil)
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.mock()
			r := &http.Request{
				Header:   c.header,
				PostForm: c.form,
				Form:     c.form,
				Method:   c.method,
			}

			req, err := fosite.NewDeviceRequest(context.Background(), r)
			if c.expectedError != nil {
				assert.EqualError(t, err, c.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.NotNil(t, req.GetRequestedAt())
			}
		})
	}
}
