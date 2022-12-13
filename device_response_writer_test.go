// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	. "github.com/ory/fosite"
	. "github.com/ory/fosite/internal"
)

func TestNewDeviceResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	handlers := []*MockDeviceEndpointHandler{NewMockDeviceEndpointHandler(ctrl)}
	dar := NewMockDeviceAuthorizeRequester(ctrl)
	defer ctrl.Finish()

	ctx := context.Background()
	oauth2 := &Fosite{Config: &Config{DeviceEndpointHandlers: DeviceEndpointHandlers{handlers[0]}}}
	duo := &Fosite{Config: &Config{DeviceEndpointHandlers: DeviceEndpointHandlers{handlers[0], handlers[0]}}}
	dar.EXPECT().SetSession(gomock.Eq(new(DefaultSession))).AnyTimes()
	fooErr := errors.New("foo")
	for k, c := range []struct {
		isErr     bool
		mock      func()
		expectErr error
	}{
		{
			mock: func() {
				handlers[0].EXPECT().HandleDeviceEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(fooErr)
			},
			isErr:     true,
			expectErr: fooErr,
		},
		{
			mock: func() {
				handlers[0].EXPECT().HandleDeviceEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			isErr: false,
		},
		{
			mock: func() {
				oauth2 = duo
				handlers[0].EXPECT().HandleDeviceEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().HandleDeviceEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			isErr: false,
		},
		{
			mock: func() {
				oauth2 = duo
				handlers[0].EXPECT().HandleDeviceEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().HandleDeviceEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(fooErr)
			},
			isErr:     true,
			expectErr: fooErr,
		},
	} {
		c.mock()
		responder, err := oauth2.NewDeviceResponse(ctx, dar)
		assert.Equal(t, c.isErr, err != nil, "%d: %s", k, err)
		if err != nil {
			assert.Equal(t, c.expectErr, err, "%d: %s", k, err)
			assert.Nil(t, responder, "%d", k)
		} else {
			assert.NotNil(t, responder, "%d", k)
		}
		t.Logf("Passed test case %d", k)
	}
}
