// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

// DeviceAuthorizeRequest is an implementation of DeviceAuthorizeRequester
type DeviceAuthorizeRequest struct {
	signature string
	Request
}

func (d *DeviceAuthorizeRequest) GetDeviceCodeSignature() string {
	return d.signature
}

func (d *DeviceAuthorizeRequest) SetDeviceCodeSignature(signature string) {
	d.signature = signature
}

func NewDeviceAuthorizeRequest() *DeviceAuthorizeRequest {
	return &DeviceAuthorizeRequest{
		Request: *NewRequest(),
	}
}
