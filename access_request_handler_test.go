// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"

	. "github.com/ory/fosite"
	"github.com/ory/fosite/internal"
)

func TestNewAccessRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	handler := internal.NewMockTokenEndpointHandler(ctrl)
	handler.EXPECT().CanHandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
	handler.EXPECT().CanSkipClientAuth(gomock.Any(), gomock.Any()).Return(false).AnyTimes()
	hasher := internal.NewMockHasher(ctrl)
	defer ctrl.Finish()

	client := &DefaultClient{}
	config := &Config{ClientSecretsHasher: hasher, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}
	fosite := &Fosite{Store: store, Config: config}
	for k, c := range []struct {
		header    http.Header
		form      url.Values
		mock      func()
		method    string
		expectErr error
		expect    *AccessRequest
		handlers  TokenEndpointHandlers
	}{
		{
			header:    http.Header{},
			expectErr: ErrInvalidRequest,
			form:      url.Values{},
			method:    "POST",
			mock:      func() {},
		},
		{
			header: http.Header{},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock:      func() {},
			expectErr: ErrInvalidRequest,
		},
		{
			header: http.Header{},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
				"client_id":  {""},
			},
			expectErr: ErrInvalidRequest,
			mock:      func() {},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(nil, errors.New(""))
			},
			handlers: TokenEndpointHandlers{handler},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "GET",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidRequest,
			mock:      func() {},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(nil, errors.New(""))
			},
			handlers: TokenEndpointHandlers{handler},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = false
				client.Secret = []byte("foo")
				hasher.EXPECT().Compare(gomock.Any(), gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(errors.New(""))
			},
			handlers: TokenEndpointHandlers{handler},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			expectErr: ErrServerError,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = false
				client.Secret = []byte("foo")
				hasher.EXPECT().Compare(gomock.Any(), gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(nil)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(ErrServerError)
			},
			handlers: TokenEndpointHandlers{handler},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = false
				client.Secret = []byte("foo")
				hasher.EXPECT().Compare(gomock.Any(), gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(nil)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: TokenEndpointHandlers{handler},
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: client,
				},
			},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = true
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: TokenEndpointHandlers{handler},
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: client,
				},
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			r := &http.Request{
				Header:   c.header,
				PostForm: c.form,
				Form:     c.form,
				Method:   c.method,
			}
			c.mock()
			ctx := NewContext()
			config.TokenEndpointHandlers = c.handlers
			ar, err := fosite.NewAccessRequest(ctx, r, new(DefaultSession))

			if c.expectErr != nil {
				assert.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
				AssertObjectKeysEqual(t, c.expect, ar, "GrantTypes", "Client")
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}

func TestNewAccessRequestWithoutClientAuth(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	handler := internal.NewMockTokenEndpointHandler(ctrl)
	handler.EXPECT().CanHandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
	handler.EXPECT().CanSkipClientAuth(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
	hasher := internal.NewMockHasher(ctrl)
	defer ctrl.Finish()

	client := &DefaultClient{}
	anotherClient := &DefaultClient{ID: "another"}
	config := &Config{ClientSecretsHasher: hasher, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}
	fosite := &Fosite{Store: store, Config: config}
	for k, c := range []struct {
		header    http.Header
		form      url.Values
		mock      func()
		method    string
		expectErr error
		expect    *AccessRequest
		handlers  TokenEndpointHandlers
	}{
		// No grant type -> error
		{
			form: url.Values{},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Times(0)
			},
			method:    "POST",
			expectErr: ErrInvalidRequest,
		},
		// No registered handlers -> error
		{
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Times(0)
			},
			method:    "POST",
			expectErr: ErrInvalidRequest,
			handlers:  TokenEndpointHandlers{},
		},
		// Handler can skip client auth and ignores missing client.
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				// despite error from storage, we should success, because client auth is not required
				store.EXPECT().GetClient(gomock.Any(), "foo").Return(nil, errors.New("no client")).Times(1)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method: "POST",
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: client,
				},
			},
			handlers: TokenEndpointHandlers{handler},
		},
		// Should pass if no auth is set in the header and can skip!
		{
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method: "POST",
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: client,
				},
			},
			handlers: TokenEndpointHandlers{handler},
		},
		// Should also pass if client auth is set!
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "foo").Return(anotherClient, nil).Times(1)
				hasher.EXPECT().Compare(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method: "POST",
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: anotherClient,
				},
			},
			handlers: TokenEndpointHandlers{handler},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			r := &http.Request{
				Header:   c.header,
				PostForm: c.form,
				Form:     c.form,
				Method:   c.method,
			}
			c.mock()
			ctx := NewContext()
			config.TokenEndpointHandlers = c.handlers
			ar, err := fosite.NewAccessRequest(ctx, r, new(DefaultSession))

			if c.expectErr != nil {
				assert.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
				AssertObjectKeysEqual(t, c.expect, ar, "GrantTypes", "Client")
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}

// In this test case one handler requires client auth and another handler not.
func TestNewAccessRequestWithMixedClientAuth(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)

	handlerWithClientAuth := internal.NewMockTokenEndpointHandler(ctrl)
	handlerWithClientAuth.EXPECT().CanHandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
	handlerWithClientAuth.EXPECT().CanSkipClientAuth(gomock.Any(), gomock.Any()).Return(false).AnyTimes()

	handlerWithoutClientAuth := internal.NewMockTokenEndpointHandler(ctrl)
	handlerWithoutClientAuth.EXPECT().CanHandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
	handlerWithoutClientAuth.EXPECT().CanSkipClientAuth(gomock.Any(), gomock.Any()).Return(true).AnyTimes()

	hasher := internal.NewMockHasher(ctrl)
	defer ctrl.Finish()

	client := &DefaultClient{}
	config := &Config{ClientSecretsHasher: hasher, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}
	fosite := &Fosite{Store: store, Config: config}
	for k, c := range []struct {
		header    http.Header
		form      url.Values
		mock      func()
		method    string
		expectErr error
		expect    *AccessRequest
		handlers  TokenEndpointHandlers
	}{
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = false
				client.Secret = []byte("foo")
				hasher.EXPECT().Compare(gomock.Any(), gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(errors.New("hash err"))
				handlerWithoutClientAuth.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method:    "POST",
			expectErr: ErrInvalidClient,
			handlers:  TokenEndpointHandlers{handlerWithoutClientAuth, handlerWithClientAuth},
		},
		{
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.Public = false
				client.Secret = []byte("foo")
				hasher.EXPECT().Compare(gomock.Any(), gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(nil)
				handlerWithoutClientAuth.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
				handlerWithClientAuth.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method: "POST",
			expect: &AccessRequest{
				GrantTypes: Arguments{"foo"},
				Request: Request{
					Client: client,
				},
			},
			handlers: TokenEndpointHandlers{handlerWithoutClientAuth, handlerWithClientAuth},
		},
		{
			header: http.Header{},
			form: url.Values{
				"grant_type": {"foo"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Times(0)
				handlerWithoutClientAuth.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil)
			},
			method:    "POST",
			expectErr: ErrInvalidRequest,
			handlers:  TokenEndpointHandlers{handlerWithoutClientAuth, handlerWithClientAuth},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			r := &http.Request{
				Header:   c.header,
				PostForm: c.form,
				Form:     c.form,
				Method:   c.method,
			}
			c.mock()
			ctx := NewContext()
			config.TokenEndpointHandlers = c.handlers
			ar, err := fosite.NewAccessRequest(ctx, r, new(DefaultSession))

			if c.expectErr != nil {
				assert.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
				AssertObjectKeysEqual(t, c.expect, ar, "GrantTypes", "Client")
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}

func basicAuth(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
}

// TestNewAccessRequest_RFC8707Resource exercises the RFC 8707 "resource"
// parameter through the full NewAccessRequest pipeline. It verifies that:
//  1. A valid "resource" parameter is parsed and surfaced on the request via
//     GetRequestedAudience(), so downstream handlers can bind the audience.
//  2. An invalid "resource" parameter (relative URI, fragment) is rejected
//     before client authentication or handler dispatch.
//  3. Existing "audience"-only requests are unaffected (backward compatibility).
func TestNewAccessRequest_RFC8707Resource(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	store := internal.NewMockStorage(ctrl)
	handler := internal.NewMockTokenEndpointHandler(ctrl)
	handler.EXPECT().CanHandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
	handler.EXPECT().CanSkipClientAuth(gomock.Any(), gomock.Any()).Return(true).AnyTimes()
	hasher := internal.NewMockHasher(ctrl)

	config := &Config{
		ClientSecretsHasher:      hasher,
		AudienceMatchingStrategy: DefaultAudienceMatchingStrategy,
		TokenEndpointHandlers:    TokenEndpointHandlers{handler},
	}
	f := &Fosite{Store: store, Config: config}

	for _, tc := range []struct {
		name         string
		form         url.Values
		wantErr      bool
		wantAudience []string
	}{
		{
			name: "resource only, single valid URI",
			form: url.Values{
				"grant_type": {"foo"},
				"resource":   {"https://mcp.example.com"},
			},
			wantAudience: []string{"https://mcp.example.com"},
		},
		{
			name: "resource only, multiple valid URIs",
			form: url.Values{
				"grant_type": {"foo"},
				"resource":   {"https://a.example.com", "https://b.example.com"},
			},
			wantAudience: []string{"https://a.example.com", "https://b.example.com"},
		},
		{
			name: "audience and resource merged",
			form: url.Values{
				"grant_type": {"foo"},
				"audience":   {"https://aud.example.com"},
				"resource":   {"https://res.example.com"},
			},
			wantAudience: []string{"https://aud.example.com", "https://res.example.com"},
		},
		{
			name: "audience only is unchanged (backward compat)",
			form: url.Values{
				"grant_type": {"foo"},
				"audience":   {"https://aud.example.com"},
			},
			wantAudience: []string{"https://aud.example.com"},
		},
		{
			name: "invalid resource (relative URI) is rejected",
			form: url.Values{
				"grant_type": {"foo"},
				"resource":   {"/relative/path"},
			},
			wantErr: true,
		},
		{
			name: "invalid resource (fragment) is rejected",
			form: url.Values{
				"grant_type": {"foo"},
				"resource":   {"https://mcp.example.com/api#section"},
			},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.wantErr {
				handler.EXPECT().HandleTokenEndpointRequest(gomock.Any(), gomock.Any()).Return(nil).Times(1)
			}

			r := &http.Request{
				Header:   http.Header{},
				PostForm: tc.form,
				Form:     tc.form,
				Method:   "POST",
			}
			ar, err := f.NewAccessRequest(context.Background(), r, new(DefaultSession))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantAudience, []string(ar.GetRequestedAudience()))
		})
	}
}
