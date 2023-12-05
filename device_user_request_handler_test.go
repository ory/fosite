// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/ory/fosite"
	. "github.com/ory/fosite/internal"
)

func TestNewDeviceUserRequest(t *testing.T) {
	var store *MockStorage
	for k, c := range []struct {
		desc          string
		conf          *Fosite
		r             *http.Request
		query         url.Values
		form          url.Values
		expectedError error
		mock          func()
		expect        *DeviceUserRequest
	}{
		/* invalid client */
		{
			desc:          "invalid client fails",
			conf:          &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query:         url.Values{"device_verifier": []string{"BBBB"}},
			expectedError: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		/* success case */
		{
			desc: "empty request should pass",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			r:    &http.Request{},
			mock: func() {},
			expect: &DeviceUserRequest{
				Request: Request{},
			},
		},
		{
			desc: "should pass",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"device_verifier": {"AAAA"},
				"client_id":       {"1234"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
				}, nil)
			},
			expect: &DeviceUserRequest{
				Request: Request{
					Client: &DefaultClient{
						GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
					},
				},
			},
		},
		{
			desc: "should pass (body)",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			form: url.Values{
				"device_verifier": {"AAAA"},
				"client_id":       {"1234"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
				}, nil)
			},
			expect: &DeviceUserRequest{
				Request: Request{
					Client: &DefaultClient{
						GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
					},
				},
			},
		},
		{
			desc: "should fail client doesn't have device grant",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"device_verifier": {"AAAA"},
				"client_id":       {"1234"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{}, nil)
			},
			expectedError: ErrInvalidGrant,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store = NewMockStorage(ctrl)
			defer ctrl.Finish()

			c.mock()
			if c.r == nil {
				c.r = &http.Request{Header: http.Header{}}
				if c.query != nil {
					c.r.URL = &url.URL{RawQuery: c.query.Encode()}
				}
				if c.form != nil {
					c.r.Method = "POST"
					c.r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					c.r.Body = io.NopCloser(strings.NewReader(c.form.Encode()))
				}
			}

			c.conf.Store = store
			ar, err := c.conf.NewDeviceUserRequest(context.Background(), c.r)
			if c.expectedError != nil {
				assert.EqualError(t, err, c.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}
