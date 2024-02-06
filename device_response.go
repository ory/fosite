// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"encoding/json"
	"io"
	"net/http"
)

type deviceResponse struct {
	Header                  http.Header
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int    `json:"interval,omitempty"`
}

type DeviceResponse struct {
	deviceResponse
}

func NewDeviceResponse() *DeviceResponse {
	return &DeviceResponse{}
}

func (d *DeviceResponse) GetDeviceCode() string {
	return d.deviceResponse.DeviceCode
}

// SetDeviceCode returns the response's user code
func (d *DeviceResponse) SetDeviceCode(code string) {
	d.deviceResponse.DeviceCode = code
}

func (d *DeviceResponse) GetUserCode() string {
	return d.deviceResponse.UserCode
}

func (d *DeviceResponse) SetUserCode(code string) {
	d.deviceResponse.UserCode = code
}

// GetVerificationURI returns the response's verification uri
func (d *DeviceResponse) GetVerificationURI() string {
	return d.deviceResponse.VerificationURI
}

func (d *DeviceResponse) SetVerificationURI(uri string) {
	d.deviceResponse.VerificationURI = uri
}

// GetVerificationURIComplete returns the response's complete verification uri if set
func (d *DeviceResponse) GetVerificationURIComplete() string {
	return d.deviceResponse.VerificationURIComplete
}

func (d *DeviceResponse) SetVerificationURIComplete(uri string) {
	d.deviceResponse.VerificationURIComplete = uri
}

// GetExpiresIn returns the response's device code and user code lifetime in seconds if set
func (d *DeviceResponse) GetExpiresIn() int64 {
	return d.deviceResponse.ExpiresIn
}

func (d *DeviceResponse) SetExpiresIn(seconds int64) {
	d.deviceResponse.ExpiresIn = seconds
}

// GetInterval returns the response's polling interval if set
func (d *DeviceResponse) GetInterval() int {
	return d.deviceResponse.Interval
}

func (d *DeviceResponse) SetInterval(seconds int) {
	d.deviceResponse.Interval = seconds
}

func (a *DeviceResponse) GetHeader() http.Header {
	return a.deviceResponse.Header
}

func (a *DeviceResponse) AddHeader(key, value string) {
	a.deviceResponse.Header.Add(key, value)
}

func (d *DeviceResponse) FromJson(r io.Reader) error {
	return json.NewDecoder(r).Decode(&d.deviceResponse)
}

func (d *DeviceResponse) ToJson(rw io.Writer) error {
	return json.NewEncoder(rw).Encode(&d.deviceResponse)
}
