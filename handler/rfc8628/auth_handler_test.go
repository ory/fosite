// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	gomock "go.uber.org/mock/gomock"

	"github.com/ory/fosite/internal"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/rfc8628"
	"github.com/ory/fosite/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_HandleDeviceEndpointRequest(t *testing.T) {
	store := storage.NewMemoryStore()
	handler := rfc8628.DeviceAuthHandler{
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

	req := &fosite.DeviceRequest{
		Request: fosite.Request{
			Client: &fosite.DefaultClient{
				Audience: []string{"https://www.ory.sh/api"},
			},
			Session: &fosite.DefaultSession{},
		},
	}
	resp := fosite.NewDeviceResponse()
	err := handler.HandleDeviceEndpointRequest(context.Background(), req, resp)

	require.NoError(t, err)
	assert.NotEmpty(t, resp.GetDeviceCode())
	assert.NotEmpty(t, resp.GetUserCode())
	assert.Equal(t, len(resp.GetUserCode()), 8)
	assert.Contains(t, resp.GetDeviceCode(), "ory_dc_")
	assert.Contains(t, resp.GetDeviceCode(), ".")
	assert.Equal(t, resp.GetVerificationURI(), "www.test.com")
}

func Test_HandleDeviceEndpointRequestWithRetry(t *testing.T) {
	var mockRFC8628CoreStorage *internal.MockRFC8628CoreStorage
	var mockRFC8628CodeStrategy *internal.MockRFC8628CodeStrategy

	ctx := context.Background()
	req := &fosite.DeviceRequest{
		Request: fosite.Request{
			Client: &fosite.DefaultClient{
				Audience: []string{"https://www.ory.sh/api"},
			},
			Session: &fosite.DefaultSession{},
		},
	}

	testCases := []struct {
		description string
		setup       func()
		check       func(t *testing.T, resp *fosite.DeviceResponse)
		expectError error
	}{
		{
			description: "should pass when generating a unique user code at the first attempt",
			setup: func() {
				mockRFC8628CodeStrategy.
					EXPECT().
					GenerateDeviceCode(ctx).
					Return("deviceCode", "signature", nil)
				mockRFC8628CoreStorage.
					EXPECT().
					CreateDeviceCodeSession(ctx, "signature", gomock.Any()).
					Return(nil)
				mockRFC8628CodeStrategy.
					EXPECT().
					GenerateUserCode(ctx).
					Return("userCode", "signature", nil).
					Times(1)
				mockRFC8628CoreStorage.
					EXPECT().
					CreateUserCodeSession(ctx, "signature", gomock.Any()).
					Return(nil).
					Times(1)
			},
			check: func(t *testing.T, resp *fosite.DeviceResponse) {
				assert.Equal(t, "userCode", resp.GetUserCode())
			},
		},
		{
			description: "should pass when generating a unique user code within allowed attempts",
			setup: func() {
				mockRFC8628CodeStrategy.
					EXPECT().
					GenerateDeviceCode(ctx).
					Return("deviceCode", "signature", nil)
				mockRFC8628CoreStorage.
					EXPECT().
					CreateDeviceCodeSession(ctx, "signature", gomock.Any()).
					Return(nil)
				gomock.InOrder(
					mockRFC8628CodeStrategy.
						EXPECT().
						GenerateUserCode(ctx).
						Return("duplicatedUserCode", "duplicatedSignature", nil),
					mockRFC8628CoreStorage.
						EXPECT().
						CreateUserCodeSession(ctx, "duplicatedSignature", gomock.Any()).
						Return(errors.New("unique constraint violation")),
					mockRFC8628CodeStrategy.
						EXPECT().
						GenerateUserCode(ctx).
						Return("uniqueUserCode", "uniqueSignature", nil),
					mockRFC8628CoreStorage.
						EXPECT().
						CreateUserCodeSession(ctx, "uniqueSignature", gomock.Any()).
						Return(nil),
				)
			},
			check: func(t *testing.T, resp *fosite.DeviceResponse) {
				assert.Equal(t, "uniqueUserCode", resp.GetUserCode())
			},
		},
		{
			description: "should fail after maximum retries to generate a unique user code",
			setup: func() {
				mockRFC8628CodeStrategy.
					EXPECT().
					GenerateDeviceCode(ctx).
					Return("deviceCode", "signature", nil)
				mockRFC8628CoreStorage.
					EXPECT().
					CreateDeviceCodeSession(ctx, "signature", gomock.Any()).
					Return(nil)
				mockRFC8628CodeStrategy.
					EXPECT().
					GenerateUserCode(ctx).
					Return("duplicatedUserCode", "duplicatedSignature", nil).
					Times(rfc8628.MaxAttempts)
				mockRFC8628CoreStorage.
					EXPECT().
					CreateUserCodeSession(ctx, "duplicatedSignature", gomock.Any()).
					Return(errors.New("unique constraint violation")).
					Times(rfc8628.MaxAttempts)
			},
			check: func(t *testing.T, resp *fosite.DeviceResponse) {
				assert.Empty(t, resp.GetUserCode())
			},
			expectError: fosite.ErrServerError,
		},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("scenario=%s", testCase.description), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockRFC8628CoreStorage = internal.NewMockRFC8628CoreStorage(ctrl)
			mockRFC8628CodeStrategy = internal.NewMockRFC8628CodeStrategy(ctrl)

			h := rfc8628.DeviceAuthHandler{
				Storage:  mockRFC8628CoreStorage,
				Strategy: mockRFC8628CodeStrategy,
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

			if testCase.setup != nil {
				testCase.setup()
			}

			resp := fosite.NewDeviceResponse()
			err := h.HandleDeviceEndpointRequest(ctx, req, resp)

			if testCase.expectError != nil {
				require.EqualError(t, err, testCase.expectError.Error(), "%+v", err)
			} else {
				require.NoError(t, err, "%+v", err)
			}

			if testCase.check != nil {
				testCase.check(t, resp)
			}
		})
	}
}
