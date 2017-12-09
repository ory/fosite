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
	"net/url"
	"testing"
	"time"

	"fmt"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResourceOwnerFlow_HandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockResourceOwnerPasswordCredentialsGrantStorage(ctrl)
	defer ctrl.Finish()

	areq := fosite.NewAccessRequest(new(fosite.DefaultSession))
	areq.Form = url.Values{}

	h := ResourceOwnerPasswordCredentialsGrantHandler{
		ResourceOwnerPasswordCredentialsGrantStorage: store,
		HandleHelper: &HandleHelper{
			AccessTokenStorage:  store,
			AccessTokenLifespan: time.Hour,
		},
		ScopeStrategy: fosite.HierarchicScopeStrategy,
	}
	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
		check       func(areq *fosite.AccessRequest)
	}{
		{
			description: "should fail because not responsible",
			expectErr:   fosite.ErrUnknownRequest,
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"123"}
			},
		},
		{
			description: "should fail because because invalid credentials",
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"password"}
				areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"password"}}
				areq.Form.Set("username", "peter")
				areq.Form.Set("password", "pan")

				store.EXPECT().Authenticate(nil, "peter", "pan").Return(fosite.ErrNotFound)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should fail because because error on lookup",
			setup: func() {
				store.EXPECT().Authenticate(nil, "peter", "pan").Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should pass",
			setup: func() {
				store.EXPECT().Authenticate(nil, "peter", "pan").Return(nil)
			},
			check: func(areq *fosite.AccessRequest) {
				assert.NotEmpty(t, areq.GetSession().GetExpiresAt(fosite.AccessToken))
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			err := h.HandleTokenEndpointRequest(nil, areq)

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
				if c.check != nil {
					c.check(areq)
				}
			}
		})
	}
}

func TestResourceOwnerFlow_PopulateTokenEndpointResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockResourceOwnerPasswordCredentialsGrantStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	rtstr := internal.NewMockRefreshTokenStrategy(ctrl)
	aresp := fosite.NewAccessResponse()
	mockAT := "accesstoken.foo.bar"
	mockRT := "refreshtoken.bar.foo"
	defer ctrl.Finish()

	areq := fosite.NewAccessRequest(nil)

	h := ResourceOwnerPasswordCredentialsGrantHandler{
		ResourceOwnerPasswordCredentialsGrantStorage: store,
		HandleHelper: &HandleHelper{
			AccessTokenStorage:  store,
			AccessTokenStrategy: chgen,
			AccessTokenLifespan: time.Hour,
		},
		RefreshTokenStrategy: rtstr,
	}
	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
		expect      func()
	}{
		{
			description: "should fail because not responsible",
			expectErr:   fosite.ErrUnknownRequest,
			setup: func() {
				areq.GrantTypes = fosite.Arguments{""}
			},
		},
		{
			description: "should pass",
			setup: func() {
				areq.Session = &fosite.DefaultSession{}
				areq.GrantTypes = fosite.Arguments{"password"}
				chgen.EXPECT().GenerateAccessToken(nil, areq).Return(mockAT, "bar", nil)
				store.EXPECT().CreateAccessTokenSession(nil, "bar", areq).Return(nil)
			},
			expect: func() {
				assert.Nil(t, aresp.GetExtra("refresh_token"), "unexpected refresh token")
			},
		},
		{
			description: "should pass - offline scope",
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"password"}
				areq.GrantScope("offline")
				rtstr.EXPECT().GenerateRefreshToken(nil, areq).Return(mockRT, "bar", nil)
				store.EXPECT().CreateRefreshTokenSession(nil, "bar", areq).Return(nil)
				chgen.EXPECT().GenerateAccessToken(nil, areq).Return(mockAT, "bar", nil)
				store.EXPECT().CreateAccessTokenSession(nil, "bar", areq).Return(nil)
			},
			expect: func() {
				assert.NotNil(t, aresp.GetExtra("refresh_token"), "expected refresh token")
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			err := h.PopulateTokenEndpointResponse(nil, areq, aresp)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
				if c.expect != nil {
					c.expect()
				}
			}
		})
	}
}
