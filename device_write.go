// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"encoding/json"
	"net/http"
)

// TODO: Do documentation

func (f *Fosite) WriteDeviceResponse(ctx context.Context, rw http.ResponseWriter, requester DeviceRequester, responder DeviceResponder) {
	// Set custom headers, e.g. "X-MySuperCoolCustomHeader" or "X-DONT-CACHE-ME"...
	wh := rw.Header()
	rh := responder.GetHeader()
	for k := range rh {
		wh.Set(k, rh.Get(k))
	}

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
		DeviceCode:              responder.GetDeviceCode(),
		UserCode:                responder.GetUserCode(),
		VerificationURI:         responder.GetVerificationURI(),
		VerificationURIComplete: responder.GetVerificationURIComplete(),
		ExpiresIn:               responder.GetExpiresIn(),
		Interval:                responder.GetInterval(),
	})
}
