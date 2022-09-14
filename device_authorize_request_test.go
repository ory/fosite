/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

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
				deviceCodeSignature: "AAAA",
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
		assert.Equal(t, c.ar.deviceCodeSignature, c.ar.GetDeviceCodeSignature(), "%d", k)
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
