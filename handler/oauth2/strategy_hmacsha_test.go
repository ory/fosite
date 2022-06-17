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

package oauth2

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/hmac"
)

var hmacshaStrategy = HMACSHAStrategy{
	Enigma: &hmac.HMACStrategy{Config: &fosite.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
	Config: &fosite.Config{
		AccessTokenLifespan:   time.Hour * 24,
		AuthorizeCodeLifespan: time.Hour * 24,
	},
}

var hmacExpiredCase = fosite.Request{
	Client: &fosite.DefaultClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},
	Session: &fosite.DefaultSession{
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken:   time.Now().UTC().Add(-time.Hour),
			fosite.AuthorizeCode: time.Now().UTC().Add(-time.Hour),
			fosite.RefreshToken:  time.Now().UTC().Add(-time.Hour),
		},
	},
}

var hmacValidCase = fosite.Request{
	Client: &fosite.DefaultClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},
	Session: &fosite.DefaultSession{
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken:   time.Now().UTC().Add(time.Hour),
			fosite.AuthorizeCode: time.Now().UTC().Add(time.Hour),
			fosite.RefreshToken:  time.Now().UTC().Add(time.Hour),
		},
	},
}

var hmacValidZeroTimeRefreshCase = fosite.Request{
	Client: &fosite.DefaultClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},
	Session: &fosite.DefaultSession{
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken:   time.Now().UTC().Add(time.Hour),
			fosite.AuthorizeCode: time.Now().UTC().Add(time.Hour),
			fosite.RefreshToken:  {},
		},
	},
}

func TestHMACAccessToken(t *testing.T) {
	for k, c := range []struct {
		r    fosite.Request
		pass bool
	}{
		{
			r:    hmacValidCase,
			pass: true,
		},
		{
			r:    hmacExpiredCase,
			pass: false,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			token, signature, err := hmacshaStrategy.GenerateAccessToken(nil, &c.r)
			assert.NoError(t, err)
			assert.Equal(t, strings.Split(token, ".")[1], signature)
			assert.Contains(t, token, "ory_at_")

			for k, token := range []string{
				token,
				strings.TrimPrefix(token, "ory_at_"),
			} {
				t.Run(fmt.Sprintf("prefix=%v", k == 0), func(t *testing.T) {
					err = hmacshaStrategy.ValidateAccessToken(nil, &c.r, token)
					if c.pass {
						assert.NoError(t, err)
						validate := hmacshaStrategy.Enigma.Signature(token)
						assert.Equal(t, signature, validate)
					} else {
						assert.Error(t, err)
					}
				})
			}
		})
	}
}

func TestHMACRefreshToken(t *testing.T) {
	for k, c := range []struct {
		r    fosite.Request
		pass bool
	}{
		{
			r:    hmacValidCase,
			pass: true,
		},
		{
			r:    hmacExpiredCase,
			pass: false,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			token, signature, err := hmacshaStrategy.GenerateRefreshToken(nil, &c.r)
			assert.NoError(t, err)
			assert.Equal(t, strings.Split(token, ".")[1], signature)
			assert.Contains(t, token, "ory_rt_")

			for k, token := range []string{
				token,
				strings.TrimPrefix(token, "ory_rt_"),
			} {
				t.Run(fmt.Sprintf("prefix=%v", k == 0), func(t *testing.T) {
					err = hmacshaStrategy.ValidateRefreshToken(nil, &c.r, token)
					if c.pass {
						assert.NoError(t, err)
						validate := hmacshaStrategy.Enigma.Signature(token)
						assert.Equal(t, signature, validate)
					} else {
						assert.Error(t, err)
					}
				})
			}
		})
	}
}

func TestHMACAuthorizeCode(t *testing.T) {
	for k, c := range []struct {
		r    fosite.Request
		pass bool
	}{
		{
			r:    hmacValidCase,
			pass: true,
		},
		{
			r:    hmacExpiredCase,
			pass: false,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			token, signature, err := hmacshaStrategy.GenerateAuthorizeCode(nil, &c.r)
			assert.NoError(t, err)
			assert.Equal(t, strings.Split(token, ".")[1], signature)
			assert.Contains(t, token, "ory_ac_")

			for k, token := range []string{
				token,
				strings.TrimPrefix(token, "ory_ac_"),
			} {
				t.Run(fmt.Sprintf("prefix=%v", k == 0), func(t *testing.T) {
					err = hmacshaStrategy.ValidateAuthorizeCode(nil, &c.r, token)
					if c.pass {
						assert.NoError(t, err)
						validate := hmacshaStrategy.Enigma.Signature(token)
						assert.Equal(t, signature, validate)
					} else {
						assert.Error(t, err)
					}
				})
			}
		})
	}
}
