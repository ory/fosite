// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDeviceAuthorizeRequest(t *testing.T) {
	for k, c := range []struct {
		ar *DeviceAuthorizeRequest
	}{
		{
			ar: NewDeviceAuthorizeRequest(),
		},
		{
			ar: &DeviceAuthorizeRequest{},
		},
		{
			ar: &DeviceAuthorizeRequest{
				Request: Request{
					Client: &DefaultClient{RedirectURIs: []string{""}},
				},
			},
		},
		{
			ar: &DeviceAuthorizeRequest{
				signature: "AAAA",
				Request: Request{
					Client: &DefaultClient{RedirectURIs: []string{""}},
				},
			},
		},
		{
			ar: &DeviceAuthorizeRequest{
				Request: Request{
					Client:         &DefaultClient{RedirectURIs: []string{"https://foobar.com/cb"}},
					RequestedAt:    time.Now().UTC(),
					RequestedScope: []string{"foo", "bar"},
				},
			},
		},
	} {
		assert.Equal(t, c.ar.Client, c.ar.GetClient(), "%d", k)
		assert.Equal(t, c.ar.signature, c.ar.GetDeviceCodeSignature(), "%d", k)
		assert.Equal(t, c.ar.RequestedAt, c.ar.GetRequestedAt(), "%d", k)
		assert.Equal(t, c.ar.RequestedScope, c.ar.GetRequestedScopes(), "%d", k)

		c.ar.GrantScope("foo")
		c.ar.SetSession(&DefaultSession{})
		c.ar.SetRequestedScopes([]string{"foo"})
		assert.True(t, c.ar.GetGrantedScopes().Has("foo"))
		assert.True(t, c.ar.GetRequestedScopes().Has("foo"))
		assert.Equal(t, &DefaultSession{}, c.ar.GetSession())
	}
}
