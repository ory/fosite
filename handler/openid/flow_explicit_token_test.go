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

package openid

import (
	"testing"

	"fmt"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleTokenEndpointRequest(t *testing.T) {
	h := &OpenIDConnectExplicitHandler{}
	areq := fosite.NewAccessRequest(nil)
	areq.Client = &fosite.DefaultClient{
		ResponseTypes: fosite.Arguments{"id_token"},
	}
	assert.EqualError(t, h.HandleTokenEndpointRequest(nil, areq), fosite.ErrUnknownRequest.Error())
}

func TestExplicit_PopulateTokenEndpointResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockOpenIDConnectRequestStorage(ctrl)
	defer ctrl.Finish()

	session := &DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject: "peter",
		},
		Headers: &jwt.Headers{},
	}
	aresp := fosite.NewAccessResponse()
	areq := fosite.NewAccessRequest(session)

	h := &OpenIDConnectExplicitHandler{
		OpenIDConnectRequestStorage: store,
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: j,
		},
	}
	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should fail because invalid response type",
			setup:       func() {},
			expectErr:   fosite.ErrUnknownRequest,
		},
		{
			description: "should fail because lookup returns not found",
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"authorization_code"}
				areq.Client = &fosite.DefaultClient{
					GrantTypes:    fosite.Arguments{"authorization_code"},
					ResponseTypes: fosite.Arguments{"id_token"},
				}
				areq.Form.Set("code", "foobar")
				store.EXPECT().GetOpenIDConnectSession(nil, "foobar", areq).Return(nil, ErrNoSessionFound)
			},
			expectErr: fosite.ErrUnknownRequest,
		},
		{
			description: "should fail because lookup fails",
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"authorization_code"}
				store.EXPECT().GetOpenIDConnectSession(nil, "foobar", areq).Return(nil, errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should fail because missing scope in original request",
			setup: func() {
				areq.GrantTypes = fosite.Arguments{"authorization_code"}
				store.EXPECT().GetOpenIDConnectSession(nil, "foobar", areq).Return(fosite.NewAuthorizeRequest(), nil)
			},
			expectErr: fosite.ErrMisconfiguration,
		},
		{
			description: "should pass",
			setup: func() {
				r := fosite.NewAuthorizeRequest()
				r.Session = areq.Session
				r.GrantedScopes = fosite.Arguments{"openid"}
				r.Form.Set("nonce", "1111111111111111")
				store.EXPECT().GetOpenIDConnectSession(nil, gomock.Any(), areq).AnyTimes().Return(r, nil)
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
			}
		})
	}
}
