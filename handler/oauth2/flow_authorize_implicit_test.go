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
	"time"

	"fmt"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeImplicit_EndpointHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockAccessTokenStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	aresp := internal.NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()

	areq := fosite.NewAuthorizeRequest()
	areq.Session = new(fosite.DefaultSession)

	h := AuthorizeImplicitGrantTypeHandler{
		AccessTokenStorage:  store,
		AccessTokenStrategy: chgen,
		AccessTokenLifespan: time.Hour,
		ScopeStrategy:       fosite.HierarchicScopeStrategy,
	}
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
			description: "should fail because persistance failed",
			setup: func() {
				chgen.EXPECT().GenerateAccessToken(nil, areq).AnyTimes().Return("access.ats", "ats", nil)
				store.EXPECT().CreateAccessTokenSession(nil, "ats", areq).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should pass",
			setup: func() {
				areq.State = "state"
				areq.GrantedScopes = fosite.Arguments{"scope"}

				store.EXPECT().CreateAccessTokenSession(nil, "ats", areq).AnyTimes().Return(nil)

				aresp.EXPECT().AddFragment("access_token", "access.ats")
				aresp.EXPECT().AddFragment("expires_in", gomock.Any())
				aresp.EXPECT().AddFragment("token_type", "bearer")
				aresp.EXPECT().AddFragment("state", "state")
				aresp.EXPECT().AddFragment("scope", "scope")
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
