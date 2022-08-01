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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
)

func TestAuthorizeImplicit_EndpointHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	areq := fosite.NewAuthorizeRequest()
	areq.Session = new(fosite.DefaultSession)
	h, store, chgen, aresp := makeAuthorizeImplicitGrantTypeHandler(ctrl)

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should pass because not responsible for handling the response type",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"a"}
			},
		},
		{
			description: "should fail because access token generation failed",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"token"}
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"implicit"},
					ResponseTypes: fosite.Arguments{"token"},
				}
				chgen.EXPECT().GenerateAccessToken(nil, areq).Return("", "", errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should fail because scope invalid",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"token"}
				areq.RequestedScope = fosite.Arguments{"scope"}
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"implicit"},
					ResponseTypes: fosite.Arguments{"token"},
				}
			},
			expectErr: fosite.ErrInvalidScope,
		},
		{
			description: "should fail because audience invalid",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"token"}
				areq.RequestedScope = fosite.Arguments{"scope"}
				areq.RequestedAudience = fosite.Arguments{"https://www.ory.sh/not-api"}
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"implicit"},
					ResponseTypes: fosite.Arguments{"token"},
					Scopes:        []string{"scope"},
					Audience:      []string{"https://www.ory.sh/api"},
				}
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should fail because persistence failed",
			setup: func() {
				areq.RequestedAudience = fosite.Arguments{"https://www.ory.sh/api"}
				chgen.EXPECT().GenerateAccessToken(nil, areq).AnyTimes().Return("access.ats", "ats", nil)
				store.EXPECT().CreateAccessTokenSession(nil, "ats", gomock.Eq(areq.Sanitize([]string{}))).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should pass",
			setup: func() {
				areq.State = "state"
				areq.GrantedScope = fosite.Arguments{"scope"}

				store.EXPECT().CreateAccessTokenSession(nil, "ats", gomock.Eq(areq.Sanitize([]string{}))).AnyTimes().Return(nil)

				aresp.EXPECT().AddParameter("access_token", "access.ats")
				aresp.EXPECT().AddParameter("expires_in", gomock.Any())
				aresp.EXPECT().AddParameter("token_type", "bearer")
				aresp.EXPECT().AddParameter("state", "state")
				aresp.EXPECT().AddParameter("scope", "scope")
			},
			expectErr: nil,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			err := h.HandleAuthorizeEndpointRequest(nil, areq, aresp)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
func makeAuthorizeImplicitGrantTypeHandler(ctrl *gomock.Controller) (AuthorizeImplicitGrantTypeHandler,
	*internal.MockAccessTokenStorage, *internal.MockAccessTokenStrategy, *internal.MockAuthorizeResponder) {
	store := internal.NewMockAccessTokenStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	aresp := internal.NewMockAuthorizeResponder(ctrl)

	h := AuthorizeImplicitGrantTypeHandler{
		AccessTokenStorage:  store,
		AccessTokenStrategy: chgen,
		Config: &fosite.Config{
			AccessTokenLifespan:      time.Hour,
			ScopeStrategy:            fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		},
	}

	return h, store, chgen, aresp
}

func TestDefaultResponseMode_AuthorizeImplicit_EndpointHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	areq := fosite.NewAuthorizeRequest()
	areq.Session = new(fosite.DefaultSession)
	h, store, chgen, aresp := makeAuthorizeImplicitGrantTypeHandler(ctrl)

	areq.State = "state"
	areq.GrantedScope = fosite.Arguments{"scope"}
	areq.ResponseTypes = fosite.Arguments{"token"}
	areq.Client = &fosite.DefaultClientWithCustomTokenLifespans{
		DefaultClient: &fosite.DefaultClient{
			GrantTypes:    fosite.Arguments{"implicit"},
			ResponseTypes: fosite.Arguments{"token"},
		},
		TokenLifespans: &internal.TestLifespans,
	}

	store.EXPECT().CreateAccessTokenSession(nil, "ats", gomock.Eq(areq.Sanitize([]string{}))).AnyTimes().Return(nil)

	aresp.EXPECT().AddParameter("access_token", "access.ats")
	aresp.EXPECT().AddParameter("expires_in", gomock.Any())
	aresp.EXPECT().AddParameter("token_type", "bearer")
	aresp.EXPECT().AddParameter("state", "state")
	aresp.EXPECT().AddParameter("scope", "scope")
	chgen.EXPECT().GenerateAccessToken(nil, areq).AnyTimes().Return("access.ats", "ats", nil)

	err := h.HandleAuthorizeEndpointRequest(nil, areq, aresp)
	assert.NoError(t, err)
	assert.Equal(t, fosite.ResponseModeFragment, areq.GetResponseMode())

	internal.RequireEqualTime(t, time.Now().UTC().Add(*internal.TestLifespans.ImplicitGrantAccessTokenLifespan), areq.Session.GetExpiresAt(fosite.AccessToken), time.Minute)
}
