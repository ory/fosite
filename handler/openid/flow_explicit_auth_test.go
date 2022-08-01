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

package openid

import (
	"context"
	"fmt"
	"testing"

	"github.com/ory/fosite/internal/gen"

	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/token/jwt"
)

// expose key to verify id_token
var key = gen.MustRSAKey()

func makeOpenIDConnectExplicitHandler(ctrl *gomock.Controller, minParameterEntropy int) (OpenIDConnectExplicitHandler, *internal.MockOpenIDConnectRequestStorage) {
	store := internal.NewMockOpenIDConnectRequestStorage(ctrl)
	config := &fosite.Config{MinParameterEntropy: minParameterEntropy}

	var j = &DefaultStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(ctx context.Context) (interface{}, error) {
				return key, nil
			},
		},
		Config: config,
	}

	return OpenIDConnectExplicitHandler{
		OpenIDConnectRequestStorage: store,
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: j,
		},
		OpenIDConnectRequestValidator: NewOpenIDConnectRequestValidator(j.Signer, config),
		Config:                        config,
	}, store
}

func TestExplicit_HandleAuthorizeEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	aresp := internal.NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()

	areq := fosite.NewAuthorizeRequest()

	session := NewDefaultSession()
	session.Claims.Subject = "foo"
	areq.Session = session

	for k, c := range []struct {
		description string
		setup       func() OpenIDConnectExplicitHandler
		expectErr   error
	}{
		{
			description: "should pass because not responsible for handling an empty response type",
			setup: func() OpenIDConnectExplicitHandler {
				h, _ := makeOpenIDConnectExplicitHandler(ctrl, fosite.MinParameterEntropy)
				areq.ResponseTypes = fosite.Arguments{""}
				return h
			},
		},
		{
			description: "should pass because scope openid is not set",
			setup: func() OpenIDConnectExplicitHandler {
				h, _ := makeOpenIDConnectExplicitHandler(ctrl, fosite.MinParameterEntropy)
				areq.ResponseTypes = fosite.Arguments{"code"}
				areq.Client = &fosite.DefaultClient{
					ResponseTypes: fosite.Arguments{"code"},
				}
				areq.RequestedScope = fosite.Arguments{""}
				return h
			},
		},
		{
			description: "should fail because no code set",
			setup: func() OpenIDConnectExplicitHandler {
				h, _ := makeOpenIDConnectExplicitHandler(ctrl, fosite.MinParameterEntropy)
				areq.GrantedScope = fosite.Arguments{"openid"}
				areq.Form.Set("nonce", "11111111111111111111111111111")
				aresp.EXPECT().GetCode().Return("")
				return h
			},
			expectErr: fosite.ErrMisconfiguration,
		},
		{
			description: "should fail because lookup fails",
			setup: func() OpenIDConnectExplicitHandler {
				h, store := makeOpenIDConnectExplicitHandler(ctrl, fosite.MinParameterEntropy)
				aresp.EXPECT().GetCode().AnyTimes().Return("codeexample")
				store.EXPECT().CreateOpenIDConnectSession(nil, "codeexample", gomock.Eq(areq.Sanitize(oidcParameters))).Return(errors.New(""))
				return h
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should pass",
			setup: func() OpenIDConnectExplicitHandler {
				h, store := makeOpenIDConnectExplicitHandler(ctrl, fosite.MinParameterEntropy)
				store.EXPECT().CreateOpenIDConnectSession(nil, "codeexample", gomock.Eq(areq.Sanitize(oidcParameters))).AnyTimes().Return(nil)
				return h
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			h := c.setup()
			err := h.HandleAuthorizeEndpointRequest(nil, areq, aresp)

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
