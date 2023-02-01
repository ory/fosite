// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/ory/fosite"
)

func TestWriteDeviceAuthorizeResponse(t *testing.T) {
	oauth2 := &Fosite{Config: &Config{
		DeviceAndUserCodeLifespan:      time.Minute,
		DeviceAuthTokenPollingInterval: time.Minute,
		DeviceVerificationURL:          "http://ory.sh",
	}}

	rw := httptest.NewRecorder()
	ar := &Request{}
	resp := &DeviceResponse{}
	resp.SetUserCode("AAAA")
	resp.SetDeviceCode("BBBB")
	resp.SetInterval(int(
		oauth2.Config.GetDeviceAuthTokenPollingInterval(context.TODO()).Round(time.Second).Seconds(),
	))
	resp.SetExpiresIn(int64(
		time.Now().Round(time.Second).Add(oauth2.Config.GetDeviceAndUserCodeLifespan(context.TODO())).Second(),
	))
	resp.SetVerificationURI(oauth2.Config.GetDeviceVerificationURL(context.TODO()))
	resp.SetVerificationURIComplete(
		oauth2.Config.GetDeviceVerificationURL(context.TODO()) + "?user_code=" + resp.GetUserCode(),
	)

	oauth2.WriteDeviceResponse(context.Background(), rw, ar, resp)

	assert.Equal(t, 200, rw.Code)

	wroteDeviceResponse := DeviceResponse{}
	err := wroteDeviceResponse.FromJson(rw.Body)
	require.NoError(t, err)

	assert.Equal(t, resp.GetUserCode(), wroteDeviceResponse.UserCode)
	assert.Equal(t, resp.GetDeviceCode(), wroteDeviceResponse.DeviceCode)
	assert.Equal(t, resp.GetVerificationURI(), wroteDeviceResponse.VerificationURI)
	assert.Equal(t, resp.GetVerificationURIComplete(), wroteDeviceResponse.VerificationURIComplete)
	assert.Equal(t, resp.GetInterval(), wroteDeviceResponse.Interval)
	assert.Equal(t, resp.GetExpiresIn(), wroteDeviceResponse.ExpiresIn)
}
