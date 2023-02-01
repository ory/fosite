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
			DeviceAuthTokenPollingInterval: time.Second * 10,
			DeviceVerificationURL:          "www.test.com",
			AccessTokenLifespan:            time.Hour,
			RefreshTokenLifespan:           time.Hour,
			ScopeStrategy:                  fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
			RefreshTokenScopes:             []string{"offline"},
		},
	}

	req := &fosite.Request{
		Session: &fosite.DefaultSession{},
	}
	resp := &fosite.DeviceResponse{}

	handler.HandleDeviceEndpointRequest(context.TODO(), req, resp)

	assert.NotEmpty(t, resp.GetDeviceCode())
	assert.NotEmpty(t, resp.GetUserCode())
	assert.Equal(t, len(resp.GetUserCode()), 8)
	assert.Contains(t, resp.GetDeviceCode(), "ory_dc_")
	assert.Contains(t, resp.GetDeviceCode(), ".")
	assert.Equal(t, resp.GetVerificationURI(), "www.test.com")
}
