// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite/internal"
	"github.com/pkg/errors"

	"github.com/stretchr/testify/require"

	"github.com/coocood/freecache"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/rfc8628"
	"github.com/ory/fosite/token/hmac"
	"github.com/ory/fosite/token/jwt"
)

func TestDeviceAuth_HandleDeviceEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	store := internal.NewMockOpenIDConnectRequestStorage(ctrl)

	config := &fosite.Config{
		MinParameterEntropy:       fosite.MinParameterEntropy,
		DeviceAndUserCodeLifespan: time.Hour * 24,
	}

	signer := &jwt.DefaultSigner{
		GetPrivateKey: func(ctx context.Context) (interface{}, error) {
			return key, nil
		},
	}

	h := OpenIDConnectDeviceHandler{
		OpenIDConnectRequestStorage: store,
		DeviceCodeStrategy: &rfc8628.DefaultDeviceStrategy{
			Enigma:           &hmac.HMACStrategy{Config: &fosite.Config{GlobalSecret: []byte("foobar")}},
			RateLimiterCache: freecache.NewCache(1024 * 1024),
			Config:           config,
		},
		Config: config,
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: &DefaultStrategy{
				Signer: signer,
				Config: config,
			},
		},
	}

	session := &DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject: "foo",
		},
		Headers: &jwt.Headers{},
	}

	client := &fosite.DefaultClient{
		ID:         "foo",
		GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
	}

	testCases := []struct {
		description string
		authreq     *fosite.DeviceRequest
		authresp    *fosite.DeviceResponse
		setup       func(authreq *fosite.DeviceRequest)
		expectErr   error
	}{
		{
			description: "should ignore because scope openid is not set",
			authreq: &fosite.DeviceRequest{
				Request: fosite.Request{
					RequestedScope: fosite.Arguments{"email"},
				},
			},
		},
		{
			description: "should ignore because client grant type is invalid",
			authreq: &fosite.DeviceRequest{
				Request: fosite.Request{
					RequestedScope: fosite.Arguments{"openid", "email"},
					Client: &fosite.DefaultClient{
						GrantTypes: []string{"authorization_code"},
					},
				},
			},
		},
		{
			description: "should fail because device code is not issued",
			authreq: &fosite.DeviceRequest{
				Request: fosite.Request{
					RequestedScope: fosite.Arguments{"openid", "email"},
					Client:         client,
				},
			},
			authresp:  &fosite.DeviceResponse{},
			expectErr: fosite.ErrMisconfiguration,
		},
		{
			description: "should fail because cannot create session",
			authreq: &fosite.DeviceRequest{
				Request: fosite.Request{
					RequestedScope: fosite.Arguments{"openid", "email"},
					Client:         client,
					Session:        session,
				},
			},
			authresp: &fosite.DeviceResponse{
				DeviceCode: "device_code",
			},
			setup: func(authreq *fosite.DeviceRequest) {
				store.
					EXPECT().
					CreateOpenIDConnectSession(gomock.Any(), gomock.Any(), gomock.Eq(authreq.Sanitize(oidcParameters))).
					Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should pass",
			authreq: &fosite.DeviceRequest{
				Request: fosite.Request{
					RequestedScope: fosite.Arguments{"openid", "email"},
					Client:         client,
					Session:        session,
				},
			},
			authresp: &fosite.DeviceResponse{
				DeviceCode: "device_code",
			},
			setup: func(authreq *fosite.DeviceRequest) {
				store.
					EXPECT().
					CreateOpenIDConnectSession(gomock.Any(), gomock.Any(), gomock.Eq(authreq.Sanitize(oidcParameters))).
					Return(nil)
			},
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case=%d/description=%s", i, testCase.description), func(t *testing.T) {
			if testCase.setup != nil {
				testCase.setup(testCase.authreq)
			}

			err := h.HandleDeviceEndpointRequest(context.Background(), testCase.authreq, testCase.authresp)
			if testCase.expectErr != nil {
				require.EqualError(t, err, testCase.expectErr.Error(), "%+v", err)
			} else {
				require.NoError(t, err, "%+v", err)
			}
		})
	}
}
