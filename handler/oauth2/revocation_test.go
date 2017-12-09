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

package oauth2

import (
	"testing"

	"fmt"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/stretchr/testify/require"
)

func TestRevokeToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockTokenRevocationStorage(ctrl)
	atStrat := internal.NewMockAccessTokenStrategy(ctrl)
	rtStrat := internal.NewMockRefreshTokenStrategy(ctrl)
	ar := internal.NewMockAccessRequester(ctrl)
	defer ctrl.Finish()

	h := TokenRevocationHandler{
		TokenRevocationStorage: store,
		RefreshTokenStrategy:   rtStrat,
		AccessTokenStrategy:    atStrat,
	}

	var token string
	var tokenType fosite.TokenType

	for k, c := range []struct {
		description string
		mock        func()
		expectErr   error
		client      fosite.Client
	}{
		{
			description: "should fail - token was issued to another client",
			expectErr:   fosite.ErrRevokationClientMismatch,
			client:      &fosite.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = fosite.RefreshToken
				rtStrat.EXPECT().RefreshTokenSignature(token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil)
				ar.EXPECT().GetClient().Return(&fosite.DefaultClient{ID: "foo"})
			},
		},
		{
			description: "should pass - refresh token discovery first; refresh token found",
			expectErr:   nil,
			client:      &fosite.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = fosite.RefreshToken
				rtStrat.EXPECT().RefreshTokenSignature(token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil)
				ar.EXPECT().GetID()
				ar.EXPECT().GetClient().Return(&fosite.DefaultClient{ID: "bar"})
				store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any())
				store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any())
			},
		},
		{
			description: "should pass - access token discovery first; access token found",
			expectErr:   nil,
			client:      &fosite.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = fosite.AccessToken
				atStrat.EXPECT().AccessTokenSignature(token)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil)
				ar.EXPECT().GetID()
				ar.EXPECT().GetClient().Return(&fosite.DefaultClient{ID: "bar"})
				store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any())
				store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any())
			},
		},
		{
			description: "should pass - refresh token discovery first; refresh token not found",
			expectErr:   nil,
			client:      &fosite.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = fosite.AccessToken
				atStrat.EXPECT().AccessTokenSignature(token)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fosite.ErrNotFound)

				rtStrat.EXPECT().RefreshTokenSignature(token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil)
				ar.EXPECT().GetID()
				ar.EXPECT().GetClient().Return(&fosite.DefaultClient{ID: "bar"})
				store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any())
				store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any())
			},
		},
		{
			description: "should pass - access token discovery first; access token not found",
			expectErr:   nil,
			client:      &fosite.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = fosite.RefreshToken
				rtStrat.EXPECT().RefreshTokenSignature(token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fosite.ErrNotFound)

				atStrat.EXPECT().AccessTokenSignature(token)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(ar, nil)
				ar.EXPECT().GetID()
				ar.EXPECT().GetClient().Return(&fosite.DefaultClient{ID: "bar"})
				store.EXPECT().RevokeRefreshToken(gomock.Any(), gomock.Any())
				store.EXPECT().RevokeAccessToken(gomock.Any(), gomock.Any())
			},
		},
		{
			description: "should fail - refresh token discovery first; both tokens not found",
			expectErr:   fosite.ErrNotFound,
			client:      &fosite.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = fosite.RefreshToken
				rtStrat.EXPECT().RefreshTokenSignature(token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fosite.ErrNotFound)

				atStrat.EXPECT().AccessTokenSignature(token)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fosite.ErrNotFound)
			},
		},
		{
			description: "should fail - access token discovery first; both tokens not found",
			expectErr:   fosite.ErrNotFound,
			client:      &fosite.DefaultClient{ID: "bar"},
			mock: func() {
				token = "foo"
				tokenType = fosite.AccessToken
				atStrat.EXPECT().AccessTokenSignature(token)
				store.EXPECT().GetAccessTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fosite.ErrNotFound)

				rtStrat.EXPECT().RefreshTokenSignature(token)
				store.EXPECT().GetRefreshTokenSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, fosite.ErrNotFound)
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.mock()
			err := h.RevokeToken(nil, token, tokenType, c.client)

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
