// Copyright © 2017 Aeneas Rekkas <aeneas+oss@aeneas.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openid

import (
	"testing"
	"time"

	"fmt"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
)

func TestJWTStrategy_GenerateIDToken(t *testing.T) {
	var req *fosite.AccessRequest
	for k, c := range []struct {
		description string
		setup       func()
		expectErr   bool
	}{
		{
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("nonce", "some-secure-nonce-state")
			},
			expectErr: false,
		},
		{
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:  "peter",
						AuthTime: time.Now().UTC(),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("nonce", "some-secure-nonce-state")
				req.Form.Set("max_age", "1234")
			},
			expectErr: false,
		},
		{
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:   "peter",
						ExpiresAt: time.Now().UTC().Add(-time.Hour),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("nonce", "some-secure-nonce-state")
			},
			expectErr: true,
		},
		{
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("nonce", "some-secure-nonce-state")
				req.Form.Set("max_age", "1234")
			},
			expectErr: true,
		},
		{
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims:  &jwt.IDTokenClaims{},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("nonce", "some-secure-nonce-state")
			},
			expectErr: true,
		},
		{
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
				})
			},
			expectErr: false,
		},
		{
			description: "should pass because max_age was requested and auth_time happened after initial request time",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:  "peter",
						AuthTime: time.Now().UTC(),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("max_age", "60")
			},
			expectErr: false,
		},
		{
			description: "should fail because max_age was requested and auth_time has expired",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:  "peter",
						AuthTime: time.Now().Add(-time.Hour).UTC(),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("max_age", "60")
			},
			expectErr: true,
		},
		{
			description: "should fail because prompt=none was requested and auth_time indicates fresh login",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().UTC(),
						RequestedAt: time.Now().Add(-time.Minute),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("prompt", "none")
			},
			expectErr: true,
		},
		{
			description: "should pass because prompt=none was requested and auth_time indicates fresh login but grant type is refresh_token",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().UTC(),
						RequestedAt: time.Now().Add(-time.Minute),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("prompt", "none")
				req.Form.Set("grant_type", "refresh_token")
			},
			expectErr: false,
		},
		{
			description: "should pass because prompt=none was requested and auth_time indicates old login",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().Add(-time.Hour).UTC(),
						RequestedAt: time.Now().Add(-time.Minute),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("prompt", "none")
			},
			expectErr: false,
		},
		{
			description: "should pass because prompt=login was requested and auth_time indicates fresh login",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().UTC(),
						RequestedAt: time.Now().Add(-time.Minute),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("prompt", "login")
			},
			expectErr: false,
		},
		{
			description: "should fail because prompt=login was requested and auth_time indicates old login",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().Add(-time.Hour).UTC(),
						RequestedAt: time.Now().Add(-time.Minute),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("prompt", "login")
			},
			expectErr: true,
		},
		{
			description: "should pass because id_token_hint subject matches subject from claims",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().Add(-time.Hour).UTC(),
						RequestedAt: time.Now().Add(-time.Minute),
					},
					Headers: &jwt.Headers{},
				})
				token, _ := j.GenerateIDToken(nil, fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
				}))
				req.Form.Set("id_token_hint", token)
			},
			expectErr: false,
		},
		{
			description: "should fail because id_token_hint subject does not match subject from claims",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().Add(-time.Hour).UTC(),
						RequestedAt: time.Now().Add(-time.Minute),
					},
					Headers: &jwt.Headers{},
				})
				token, _ := j.GenerateIDToken(nil, fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{Subject: "alice"}, Headers: &jwt.Headers{},
				}))
				req.Form.Set("id_token_hint", token)
			},
			expectErr: true,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.setup()
			token, err := j.GenerateIDToken(nil, req)
			assert.Equal(t, c.expectErr, err != nil, "%d: %s", k, err)
			if !c.expectErr {
				assert.NotEmpty(t, token)
			}
		})
	}
}
