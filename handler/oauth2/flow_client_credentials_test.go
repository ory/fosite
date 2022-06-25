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

package oauth2

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
)

func TestClientCredentials_HandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockClientCredentialsGrantStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	areq := internal.NewMockAccessRequester(ctrl)
	defer ctrl.Finish()

	h := ClientCredentialsGrantHandler{
		HandleHelper: &HandleHelper{
			AccessTokenStorage:  store,
			AccessTokenStrategy: chgen,
			Config: &fosite.Config{
				AccessTokenLifespan: time.Hour,
			},
		},
		Config: &fosite.Config{
			ScopeStrategy:            fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		},
	}
	for k, c := range []struct {
		description string
		mock        func()
		req         *http.Request
		expectErr   error
	}{
		{
			description: "should fail because not responsible",
			expectErr:   fosite.ErrUnknownRequest,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{""})
			},
		},
		{
			description: "should fail because audience not valid",
			expectErr:   fosite.ErrInvalidRequest,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"client_credentials"})
				areq.EXPECT().GetRequestedScopes().Return([]string{})
				areq.EXPECT().GetRequestedAudience().Return([]string{"https://www.ory.sh/not-api"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					GrantTypes: fosite.Arguments{"client_credentials"},
					Audience:   []string{"https://www.ory.sh/api"},
				})
			},
		},
		{
			description: "should fail because scope not valid",
			expectErr:   fosite.ErrInvalidScope,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"client_credentials"})
				areq.EXPECT().GetRequestedScopes().Return([]string{"foo", "bar", "baz.bar"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					GrantTypes: fosite.Arguments{"client_credentials"},
					Scopes:     []string{"foo"},
				})
			},
		},
		{
			description: "should pass",
			mock: func() {
				areq.EXPECT().GetSession().Return(new(fosite.DefaultSession))
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"client_credentials"})
				areq.EXPECT().GetRequestedScopes().Return([]string{"foo", "bar", "baz.bar"})
				areq.EXPECT().GetRequestedAudience().Return([]string{})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					GrantTypes: fosite.Arguments{"client_credentials"},
					Scopes:     []string{"foo", "bar", "baz"},
				})
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.mock()
			err := h.HandleTokenEndpointRequest(nil, areq)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestClientCredentials_PopulateTokenEndpointResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockClientCredentialsGrantStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	areq := fosite.NewAccessRequest(new(fosite.DefaultSession))
	aresp := fosite.NewAccessResponse()
	defer ctrl.Finish()

	h := ClientCredentialsGrantHandler{
		HandleHelper: &HandleHelper{
			AccessTokenStorage:  store,
			AccessTokenStrategy: chgen,
			Config: &fosite.Config{
				AccessTokenLifespan: time.Hour,
			},
		},
		Config: &fosite.Config{
			ScopeStrategy: fosite.HierarchicScopeStrategy,
		},
	}
	for k, c := range []struct {
		description string
		mock        func()
		req         *http.Request
		expectErr   error
	}{
		{
			description: "should fail because not responsible",
			expectErr:   fosite.ErrUnknownRequest,
			mock: func() {
				areq.GrantTypes = fosite.Arguments{""}
			},
		},
		{
			description: "should fail because grant_type not allowed",
			expectErr:   fosite.ErrUnauthorizedClient,
			mock: func() {
				areq.GrantTypes = fosite.Arguments{"client_credentials"}
				areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"authorization_code"}}
			},
		},
		{
			description: "should pass",
			mock: func() {
				areq.GrantTypes = fosite.Arguments{"client_credentials"}
				areq.Session = &fosite.DefaultSession{}
				areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"client_credentials"}}
				chgen.EXPECT().GenerateAccessToken(nil, areq).Return("tokenfoo.bar", "bar", nil)
				store.EXPECT().CreateAccessTokenSession(nil, "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.mock()
			err := h.PopulateTokenEndpointResponse(nil, areq, aresp)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
