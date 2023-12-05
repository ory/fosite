// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import "net/http"

type DeviceUserResponse struct {
	Header http.Header
}

func NewDeviceUserResponse() *DeviceUserResponse {
	return &DeviceUserResponse{}
}

func (a *DeviceUserResponse) GetHeader() http.Header {
	return a.Header
}

func (a *DeviceUserResponse) AddHeader(key, value string) {
	a.Header.Add(key, value)
}
