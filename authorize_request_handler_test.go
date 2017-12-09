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
	"net/http"
	"net/url"
	"testing"

	"context"

	"fmt"

	"github.com/golang/mock/gomock"
	. "github.com/ory/fosite"
	. "github.com/ory/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Should pass
//
// * https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Terminology
//   The OAuth 2.0 specification allows for registration of space-separated response_type parameter values.
//   If a Response Type contains one of more space characters (%20), it is compared as a space-delimited list of
//   values in which the order of values does not matter.
func TestNewAuthorizeRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := NewMockStorage(ctrl)
	defer ctrl.Finish()

	redir, _ := url.Parse("https://foo.bar/cb")
	for k, c := range []struct {
		desc          string
		conf          *Fosite
		r             *http.Request
		query         url.Values
		expectedError error
		mock          func()
		expect        *AuthorizeRequest
	}{
		/* empty request */
		{
			desc:          "empty request fails",
			conf:          &Fosite{Store: store},
			r:             &http.Request{},
			expectedError: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		/* invalid redirect uri */
		{
			desc:          "invalid redirect uri fails",
			conf:          &Fosite{Store: store},
			query:         url.Values{"redirect_uri": []string{"invalid"}},
			expectedError: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		/* invalid client */
		{
			desc:          "invalid client fails",
			conf:          &Fosite{Store: store},
			query:         url.Values{"redirect_uri": []string{"https://foo.bar/cb"}},
			expectedError: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		/* redirect client mismatch */
		{
			desc: "client and request redirects mismatch",
			conf: &Fosite{Store: store},
			query: url.Values{
				"client_id": []string{"1234"},
			},
			expectedError: ErrInvalidRequest,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"invalid"}}, nil)
			},
		},
		/* redirect client mismatch */
		{
			desc: "client and request redirects mismatch",
			conf: &Fosite{Store: store},
			query: url.Values{
				"redirect_uri": []string{""},
				"client_id":    []string{"1234"},
			},
			expectedError: ErrInvalidRequest,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"invalid"}}, nil)
			},
		},
		/* redirect client mismatch */
		{
			desc: "client and request redirects mismatch",
			conf: &Fosite{Store: store},
			query: url.Values{
				"redirect_uri": []string{"https://foo.bar/cb"},
				"client_id":    []string{"1234"},
			},
			expectedError: ErrInvalidRequest,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"invalid"}}, nil)
			},
		},
		/* no state */
		{
			desc: "no state",
			conf: &Fosite{Store: store},
			query: url.Values{
				"redirect_uri":  []string{"https://foo.bar/cb"},
				"client_id":     []string{"1234"},
				"response_type": []string{"code"},
			},
			expectedError: ErrInvalidState,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}}, nil)
			},
		},
		/* short state */
		{
			desc: "short state",
			conf: &Fosite{Store: store},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code"},
				"state":         {"short"},
			},
			expectedError: ErrInvalidState,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}}, nil)
			},
		},
		/* success case */
		{
			desc: "should pass",
			conf: &Fosite{Store: store},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code token"},
				"state":         {"strong-state"},
				"scope":         {"foo bar"},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{"code", "token"},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}},
					Scopes: []string{"foo", "bar"},
				},
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.mock()
			if c.r == nil {
				c.r = &http.Request{Header: http.Header{}}
				if c.query != nil {
					c.r.URL = &url.URL{RawQuery: c.query.Encode()}
				}
			}

			ar, err := c.conf.NewAuthorizeRequest(context.Background(), c.r)
			if c.expectedError != nil {
				assert.EqualError(t, errors.Cause(err), c.expectedError.Error())
			} else {
				require.NoError(t, err)
				AssertObjectKeysEqual(t, c.expect, ar, "ResponseTypes", "Scopes", "Client", "RedirectURI", "State")
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}
