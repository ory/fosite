package fosite

import (
	"encoding/json"
	"net/http"
)

func (f *Fosite) WriteDeviceAuthorizeResponse(rw http.ResponseWriter, r Requester, resp DeviceAuthorizeResponder) {
	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	_ = json.NewEncoder(rw).Encode(struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
		ExpiresIn               int64  `json:"expires_in"`
		Interval                int    `json:"interval,omitempty"`
	}{
		DeviceCode:              resp.GetDeviceCode(),
		UserCode:                resp.GetUserCode(),
		VerificationURI:         resp.GetVerificationURI(),
		VerificationURIComplete: resp.GetVerificationURIComplete(),
		ExpiresIn:               resp.GetExpiresIn(),
		Interval:                resp.GetInterval(),
	})
}
