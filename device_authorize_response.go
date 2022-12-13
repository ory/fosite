// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import "net/http"

type DeviceAuthorizeResponse struct {
	Header http.Header
}

func NewDeviceAuthorizeResponse() *DeviceAuthorizeResponse {
	return &DeviceAuthorizeResponse{}
}

func (a *DeviceAuthorizeResponse) GetHeader() http.Header {
	return a.Header
}

func (a *DeviceAuthorizeResponse) AddHeader(key, value string) {
	a.Header.Add(key, value)
}
