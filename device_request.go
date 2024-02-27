// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

// DeviceRequest is an implementation of DeviceRequester
type DeviceRequest struct {
	Request
}

// NewDeviceRequest returns a new device request
func NewDeviceRequest() *DeviceRequest {
	return &DeviceRequest{
		Request: *NewRequest(),
	}
}
