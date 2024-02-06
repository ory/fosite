// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	. "github.com/ory/fosite/handler/rfc8628"
	"github.com/ory/fosite/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_HandleDeviceEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	store := storage.NewMemoryStore()
	handler := DeviceAuthHandler{
		Storage:  store,
		Strategy: &hmacshaStrategy,
		Config: &fosite.Config{
			DeviceAndUserCodeLifespan:      time.Minute * 10,
			DeviceAuthTokenPollingInterval: time.Second * 5,
			DeviceVerificationURL:          "www.test.com",
			AccessTokenLifespan:            time.Hour,
			RefreshTokenLifespan:           time.Hour,
			ScopeStrategy:                  fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
			RefreshTokenScopes:             []string{"offline"},
		},
	}

	for _, c := range []struct {
		handler     DeviceAuthHandler
		req         *fosite.DeviceRequest
		description string
		expectErr   error
		expect      func(t *testing.T, req *fosite.DeviceRequest, resp *fosite.DeviceResponse)
	}{
		{
			handler: handler,
			req: &fosite.DeviceRequest{
				Request: fosite.Request{
					Client: &fosite.DefaultClient{
						Audience: []string{"https://www.ory.sh/api"},
					},
					Session: &fosite.DefaultSession{},
				},
			},
			expect: func(t *testing.T, req *fosite.DeviceRequest, resp *fosite.DeviceResponse) {
				assert.NotEmpty(t, resp.GetDeviceCode())
				assert.NotEmpty(t, resp.GetUserCode())
				assert.Equal(t, len(resp.GetUserCode()), 8)
				assert.Contains(t, resp.GetDeviceCode(), "ory_dc_")
				assert.Contains(t, resp.GetDeviceCode(), ".")
				assert.Equal(t, resp.GetVerificationURI(), "www.test.com")
			},
		},
	} {
		t.Run("case="+c.description, func(t *testing.T) {
			resp := fosite.NewDeviceResponse()
			err := c.handler.HandleDeviceEndpointRequest(context.Background(), c.req, resp)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}

			if c.expect != nil {
				c.expect(t, c.req, resp)
			}
		})
	}
}
