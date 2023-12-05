// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

// DeviceUserRequest is an implementation of DeviceUserRequester
type DeviceUserRequest struct {
	signature string
	Request
}

func (d *DeviceUserRequest) GetDeviceCodeSignature() string {
	return d.signature
}

func (d *DeviceUserRequest) SetDeviceCodeSignature(signature string) {
	d.signature = signature
}

func NewDeviceUserRequest() *DeviceUserRequest {
	return &DeviceUserRequest{
		Request: *NewRequest(),
	}
}
