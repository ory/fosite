package fosite

import "context"

type DeviceAuthorizeResponse struct {
	context                 context.Context
	deviceCode              string
	userCode                string
	verificationURI         string
	verificationURIComplete string
	interval                int
	expiresIn               int64
}

// GetDeviceCode returns the response's device code
func NewDeviceAuthorizeResponse() *DeviceAuthorizeResponse {
	return &DeviceAuthorizeResponse{}
}

func (d *DeviceAuthorizeResponse) GetDeviceCode() string {
	return d.deviceCode
}

// GetUserCode returns the response's user code
func (d *DeviceAuthorizeResponse) SetDeviceCode(code string) {
	d.deviceCode = code
}

func (d *DeviceAuthorizeResponse) GetUserCode() string {
	return d.userCode
}

func (d *DeviceAuthorizeResponse) SetUserCode(code string) {
	d.userCode = code
}

// GetVerificationURI returns the response's verification uri
func (d *DeviceAuthorizeResponse) GetVerificationURI() string {
	return d.verificationURI
}

func (d *DeviceAuthorizeResponse) SetVerificationURI(uri string) {
	d.verificationURI = uri
}

// GetVerificationURIComplete returns the response's complete verification uri if set
func (d *DeviceAuthorizeResponse) GetVerificationURIComplete() string {
	return d.verificationURIComplete
}

func (d *DeviceAuthorizeResponse) SetVerificationURIComplete(uri string) {
	d.verificationURIComplete = uri
}

// GetExpiresIn returns the response's device code and user code lifetime in seconds if set
func (d *DeviceAuthorizeResponse) GetExpiresIn() int64 {
	return d.expiresIn
}

func (d *DeviceAuthorizeResponse) SetExpiresIn(seconds int64) {
	d.expiresIn = seconds
}

// GetInterval returns the response's polling interval if set
func (d *DeviceAuthorizeResponse) GetInterval() int {
	return d.interval
}

func (d *DeviceAuthorizeResponse) SetInterval(seconds int) {
	d.interval = seconds
}
