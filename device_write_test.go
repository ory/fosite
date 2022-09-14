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

package fosite_test

import (
	"context"
	"encoding/json"
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
	var params struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
		ExpiresIn               int64  `json:"expires_in"`
		Interval                int    `json:"interval,omitempty"`
	}

	assert.Equal(t, 200, rw.Code)
	err := json.NewDecoder(rw.Body).Decode(&params)
	require.NoError(t, err)

	assert.Equal(t, resp.GetUserCode(), params.UserCode)
	assert.Equal(t, resp.GetDeviceCode(), params.DeviceCode)
	assert.Equal(t, resp.GetVerificationURI(), params.VerificationURI)
	assert.Equal(t, resp.GetVerificationURIComplete(), params.VerificationURIComplete)
	assert.Equal(t, resp.GetInterval(), params.Interval)
	assert.Equal(t, resp.GetExpiresIn(), params.ExpiresIn)
}
