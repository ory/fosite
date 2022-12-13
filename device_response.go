// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import "net/http"

type DeviceResponse struct {
	Header                  http.Header
	deviceCode              string
	userCode                string
	verificationURI         string
	verificationURIComplete string
	interval                int
	expiresIn               int64
}

func NewDeviceResponse() *DeviceResponse {
	return &DeviceResponse{}
}

func (d *DeviceResponse) GetDeviceCode() string {
	return d.deviceCode
}

// GetUserCode returns the response's user code
func (d *DeviceResponse) SetDeviceCode(code string) {
	d.deviceCode = code
}

func (d *DeviceResponse) GetUserCode() string {
	return d.userCode
}

func (d *DeviceResponse) SetUserCode(code string) {
	d.userCode = code
}

// GetVerificationURI returns the response's verification uri
func (d *DeviceResponse) GetVerificationURI() string {
	return d.verificationURI
}

func (d *DeviceResponse) SetVerificationURI(uri string) {
	d.verificationURI = uri
}

// GetVerificationURIComplete returns the response's complete verification uri if set
func (d *DeviceResponse) GetVerificationURIComplete() string {
	return d.verificationURIComplete
}

func (d *DeviceResponse) SetVerificationURIComplete(uri string) {
	d.verificationURIComplete = uri
}

// GetExpiresIn returns the response's device code and user code lifetime in seconds if set
func (d *DeviceResponse) GetExpiresIn() int64 {
	return d.expiresIn
}

func (d *DeviceResponse) SetExpiresIn(seconds int64) {
	d.expiresIn = seconds
}

// GetInterval returns the response's polling interval if set
func (d *DeviceResponse) GetInterval() int {
	return d.interval
}

func (d *DeviceResponse) SetInterval(seconds int) {
	d.interval = seconds
}

func (a *DeviceResponse) GetHeader() http.Header {
	return a.Header
}

func (a *DeviceResponse) AddHeader(key, value string) {
	a.Header.Add(key, value)
}
