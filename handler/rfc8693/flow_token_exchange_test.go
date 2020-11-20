/*
 * Copyright © 2020 Bosch.IO, Germany
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
 * @author		Miguel Paulos Nunes <Miguel.PaulosNunes@bosch.io>, Olaf Märker <Olaf.Maerker@bosch.io>
 * @copyright 	2020 Bosch.IO, Germany
 * @license 	Apache-2.0
 *
 */

package rfc8693

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"

	"github.com/ory/fosite/internal"

	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
)

func TestTokenExchange_HandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockClientCredentialsGrantStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	areq := internal.NewMockTokenExchangeAccessRequester(ctrl)
	delegatedAreq := internal.NewMockAccessRequester(ctrl)
	coreStore := internal.NewMockCoreStorage(ctrl)
	coreChgen := internal.NewMockCoreStrategy(ctrl)
	storage := internal.NewMockStorage(ctrl)
	defer ctrl.Finish()

	h := TokenExchangeGrantHandler{
		AccessTokenStrategy:      chgen,
		AccessTokenStorage:       store,
		AccessTokenLifespan:      time.Hour,
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		CoreStorage:              coreStore,
		CoreStrategy:             coreChgen,
		Store:                    storage,
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
			description: "should fail because subject_token not set",
			expectErr:   fosite.ErrInvalidRequest.WithHint("Mandatory parameter subject_token is missing."),
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"},
					Audience:   []string{"https://www.ory.sh/api"},
				})
				query, _ := url.ParseQuery("")
				areq.EXPECT().GetRequestForm().Return(query)
			},
		},
		{
			description: "should fail because subject_token_type not set",
			expectErr:   fosite.ErrInvalidRequest.WithHint("Mandatory parameter subject_token_type is missing."),
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"},
					Audience:   []string{"https://www.ory.sh/api"},
				})
				query, _ := url.ParseQuery("subject_token=ABCD.1234")
				areq.EXPECT().GetRequestForm().Return(query)
			},
		},
		{
			description: "should fail because client cannot exchange its own token",
			expectErr:   fosite.ErrRequestForbidden.WithHint("Clients are not allowed to perform a token exchange on their own tokens"),
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"})
				query, _ := url.ParseQuery("subject_token=ABCD.1234&subject_token_type=urn:ietf:params:oauth:token-type:access_token")
				areq.EXPECT().GetRequestForm().Return(query)
				exchangeClient := &fosite.DefaultClient{
					ID:         "exchange-client",
					GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"},
					Audience:   []string{"https://www.ory.sh/api"},
				}
				areq.EXPECT().GetClient().Return(exchangeClient)
				areq.EXPECT().GetSession()
				coreChgen.EXPECT().AccessTokenSignature("ABCD.1234").Return("1234")
				coreStore.EXPECT().GetAccessTokenSession(nil, "1234", nil).Return(delegatedAreq, nil)
				coreChgen.EXPECT().ValidateAccessToken(nil, delegatedAreq, "ABCD.1234").Return(nil)

				delegatedAreq.EXPECT().GetSubjectTokenClient().Times(2).Return(exchangeClient)
			},
		},
		{
			description: "should fail because allowed actor not set",
			expectErr:   fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to perform a token exchange for the given subject token."),
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"})
				query, _ := url.ParseQuery("subject_token=ABCD.1234&subject_token_type=urn:ietf:params:oauth:token-type:access_token")
				areq.EXPECT().GetRequestForm().Return(query)
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					ID:         "exchange-client",
					GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"},
					Audience:   []string{"https://www.ory.sh/api"},
				})
				areq.EXPECT().GetSession()
				coreChgen.EXPECT().AccessTokenSignature("ABCD.1234").Return("1234")
				coreStore.EXPECT().GetAccessTokenSession(nil, "1234", nil).Return(delegatedAreq, nil)
				coreChgen.EXPECT().ValidateAccessToken(nil, delegatedAreq, "ABCD.1234").Return(nil)

				subjectTokenClient := &fosite.DefaultClient{}
				delegatedAreq.EXPECT().GetSubjectTokenClient().Times(2).Return(subjectTokenClient)
				storage.EXPECT().GetClient(nil, "").Return(subjectTokenClient, nil)
			},
		},
		{
			description: "should fail because audience not valid",
			expectErr:   fosite.ErrInvalidTarget.WithHint("Requested audience \"https://www.ory.sh/not-api\" has not been whitelisted by the OAuth 2.0 Client."),
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"})
				query, _ := url.ParseQuery("subject_token=ABCD.1234&subject_token_type=urn:ietf:params:oauth:token-type:access_token")
				areq.EXPECT().GetRequestForm().Return(query)
				exchangeClient := &fosite.DefaultClient{
					ID:         "exchange-client",
					GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"},
					Audience:   []string{"https://www.ory.sh/api"},
				}
				areq.EXPECT().GetClient().Return(exchangeClient)
				areq.EXPECT().GetSession()
				coreChgen.EXPECT().AccessTokenSignature("ABCD.1234").Return("1234")
				coreStore.EXPECT().GetAccessTokenSession(nil, "1234", nil).Return(delegatedAreq, nil)
				coreChgen.EXPECT().ValidateAccessToken(nil, delegatedAreq, "ABCD.1234").Return(nil)

				subjectTokenClient := &fosite.DefaultClient{
					MayAct: []string{"exchange-client"},
				}
				delegatedAreq.EXPECT().GetSubjectTokenClient().Return(nil)
				delegatedAreq.EXPECT().GetClient().Return(subjectTokenClient)
				storage.EXPECT().GetClient(nil, "").Return(subjectTokenClient, nil)
				areq.EXPECT().SetSubjectTokenClient(subjectTokenClient)

				areq.EXPECT().GetRequestedScopes().Return([]string{})
				areq.EXPECT().GetRequestedAudience().Return([]string{"https://www.ory.sh/not-api"})
			},
		},
		{
			description: "should fail because scope not valid",
			expectErr:   fosite.ErrInvalidScope.WithHint("The OAuth 2.0 Client is not allowed to request scope \"bar\"."),
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"})
				query, _ := url.ParseQuery("subject_token=ABCD.1234&subject_token_type=urn:ietf:params:oauth:token-type:access_token")
				areq.EXPECT().GetRequestForm().Return(query)

				areq.EXPECT().GetSession()
				coreChgen.EXPECT().AccessTokenSignature("ABCD.1234").Return("1234")
				coreStore.EXPECT().GetAccessTokenSession(nil, "1234", nil).Return(delegatedAreq, nil)
				coreChgen.EXPECT().ValidateAccessToken(nil, delegatedAreq, "ABCD.1234").Return(nil)

				subjectTokenClient := &fosite.DefaultClient{
					MayAct: []string{"exchange-client"},
				}
				delegatedAreq.EXPECT().GetSubjectTokenClient().Times(2).Return(subjectTokenClient)
				storage.EXPECT().GetClient(nil, "").Return(subjectTokenClient, nil)
				areq.EXPECT().SetSubjectTokenClient(subjectTokenClient)

				delegatedAreq.EXPECT().GetGrantedScopes()

				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					ID:         "exchange-client",
					GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"},
					Audience:   []string{"https://www.ory.sh/api"},
					Scopes:     []string{"foo"},
				})

				areq.EXPECT().GetRequestedScopes().Return([]string{"foo", "bar", "baz.bar"})
			},
		},
		{
			description: "should pass",
			mock: func() {
				session := new(fosite.DefaultSession)
				areq.EXPECT().GetSession().AnyTimes().Return(session)
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"})
				query, _ := url.ParseQuery("subject_token=ABCD.1234&subject_token_type=urn:ietf:params:oauth:token-type:access_token")
				areq.EXPECT().GetRequestForm().Return(query)

				coreChgen.EXPECT().AccessTokenSignature("ABCD.1234").Return("1234")
				coreStore.EXPECT().GetAccessTokenSession(nil, "1234", session).Return(delegatedAreq, nil)
				coreChgen.EXPECT().ValidateAccessToken(nil, delegatedAreq, "ABCD.1234").Return(nil)

				subjectTokenClient := &fosite.DefaultClient{
					MayAct: []string{"exchange-client"},
				}
				delegatedAreq.EXPECT().GetSubjectTokenClient().Times(2).Return(subjectTokenClient)
				storage.EXPECT().GetClient(nil, "").Return(subjectTokenClient, nil)
				areq.EXPECT().SetSubjectTokenClient(subjectTokenClient)

				areq.EXPECT().GetRequestedScopes().Return([]string{"foo", "bar", "baz.bar"})
				areq.EXPECT().GetRequestedAudience().Return([]string{})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					ID:         "exchange-client",
					GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"},
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
				require.Equal(t, c.expectErr.(*fosite.RFC6749Error).Hint, errors.Unwrap(err).(*fosite.RFC6749Error).Hint)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTokenExchange_PopulateTokenEndpointResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockClientCredentialsGrantStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	refresh := internal.NewMockRefreshTokenStrategy(ctrl)
	areq := fosite.NewAccessRequest(new(fosite.DefaultSession))
	aresp := fosite.NewAccessResponse()
	defer ctrl.Finish()

	h := TokenExchangeGrantHandler{
		AccessTokenStrategy:  chgen,
		AccessTokenStorage:   store,
		RefreshTokenStrategy: refresh,
		AccessTokenLifespan:  time.Hour,
		RefreshTokenScopes:   []string{"offline", "offline_access"},
		ScopeStrategy:        fosite.HierarchicScopeStrategy,
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
			description: "should fail because client not allowed",
			expectErr:   fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:token-exchange\"."),
			mock: func() {
				areq.GrantTypes = fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"}
				areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"foo"}}
			},
		},
		{
			description: "should pass but without including a refresh token",
			mock: func() {
				areq.GrantTypes = fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"}
				areq.Session = &fosite.DefaultSession{}
				areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"}}
				chgen.EXPECT().GenerateAccessToken(nil, areq).Times(1).Return("tokenfoo.bar", "bar", nil)
				refresh.EXPECT().GenerateRefreshToken(nil, areq).Times(0)
				store.EXPECT().CreateAccessTokenSession(nil, "bar", gomock.Eq(areq.Sanitize([]string{}))).Times(1).Return(nil)
			},
		},
		{
			description: "should pass and include a refresh token",
			mock: func() {
				areq.GrantTypes = fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"}
				areq.Session = &fosite.DefaultSession{}
				areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"}}
				areq.GrantScope("offline")
				chgen.EXPECT().GenerateAccessToken(nil, areq).Times(1).Return("tokenfoo.bar", "bar", nil)
				refresh.EXPECT().GenerateRefreshToken(nil, areq).Times(1).Return("refreshfoo.bar", "", nil)
				store.EXPECT().CreateAccessTokenSession(nil, "bar", gomock.Eq(areq.Sanitize([]string{}))).Times(1).Return(nil)

			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.mock()
			err := h.PopulateTokenEndpointResponse(nil, areq, aresp)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
				require.Equal(t, c.expectErr.(*fosite.RFC6749Error).Hint, errors.Unwrap(err).(*fosite.RFC6749Error).Hint)
			} else {
				require.NoError(t, err)
				require.Equal(t, aresp.GetExtra("issued_token_type").(string), "urn:ietf:params:oauth:token-type:access_token")
			}
		})
	}
}
