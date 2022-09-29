/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

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
	. "github.com/ory/fosite/internal"
)

func TestNewDeviceAuthorizeRequest(t *testing.T) {
	var store *MockStorage
	for k, c := range []struct {
		desc          string
		conf          *Fosite
		r             *http.Request
		query         url.Values
		expectedError error
		mock          func()
		expect        *DeviceAuthorizeRequest
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
			expect: &DeviceAuthorizeRequest{
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
			expect: &DeviceAuthorizeRequest{
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
			}

			c.conf.Store = store
			ar, err := c.conf.NewDeviceAuthorizeRequest(context.Background(), c.r)
			if c.expectedError != nil {
				assert.EqualError(t, err, c.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}
