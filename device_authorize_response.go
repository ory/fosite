package fosite

import "context"

type DeviceAuthorizeResponse struct {
	context             context.Context
	deviceCode          string
	userCode            string
	verificationURI     string
	verificationURIfull string
	interval            int
	expiresIn           int64
}

func NewDeviceAuthorizeResponse() *DeviceAuthorizeResponse {
	return &DeviceAuthorizeResponse{}
}

func (d *DeviceAuthorizeResponse) GetDeviceCode() string {
	return d.deviceCode
}

func (d *DeviceAuthorizeResponse) SetDeviceCode(code string) {
	d.deviceCode = code
}

func (d *DeviceAuthorizeResponse) GetUserCode() string {
	return d.userCode
}

func (d *DeviceAuthorizeResponse) SetUserCode(code string) {
	d.userCode = code
}

func (d *DeviceAuthorizeResponse) GetVerificationURI() string {
	return d.verificationURI
}

func (d *DeviceAuthorizeResponse) SetVerificationURI(uri string) {
	d.verificationURI = uri
}

func (d *DeviceAuthorizeResponse) GetVerificationURIComplete() string {
	return d.verificationURIfull
}

func (d *DeviceAuthorizeResponse) SetVerificationURIComplete(uri string) {
	d.verificationURIfull = uri
}

func (d *DeviceAuthorizeResponse) GetExpiresIn() int64 {
	return d.expiresIn
}

func (d *DeviceAuthorizeResponse) SetExpiresIn(seconds int64) {
	d.expiresIn = seconds
}

func (d *DeviceAuthorizeResponse) GetInterval() int {
	return d.interval
}

func (d *DeviceAuthorizeResponse) SetInterval(seconds int) {
	d.interval = seconds
}
