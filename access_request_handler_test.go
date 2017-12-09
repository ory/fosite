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

package fosite_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAccessRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	client := internal.NewMockClient(ctrl)
	handler := internal.NewMockTokenEndpointHandler(ctrl)
	hasher := internal.NewMockHasher(ctrl)
	defer ctrl.Finish()

	fosite := &Fosite{Store: store, Hasher: hasher}
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
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("foo"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(errors.New(""))
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
			expectErr: ErrServerError,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("foo"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(nil)
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
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("foo"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("foo")), gomock.Eq([]byte("bar"))).Return(nil)
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
				client.EXPECT().IsPublic().Return(true)
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
			fosite.TokenEndpointHandlers = c.handlers
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
