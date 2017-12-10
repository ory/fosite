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

package oauth2

import (
	"strings"
	"testing"
	"time"

	"fmt"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/hmac"
	"github.com/stretchr/testify/assert"
)

var hmacshaStrategy = HMACSHAStrategy{
	Enigma:                &hmac.HMACStrategy{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")},
	AccessTokenLifespan:   time.Hour * 24,
	AuthorizeCodeLifespan: time.Hour * 24,
}

var hmacExpiredCase = fosite.Request{
	Client: &fosite.DefaultClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},
	Session: &fosite.DefaultSession{
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken:   time.Now().UTC().Add(-time.Hour),
			fosite.AuthorizeCode: time.Now().UTC().Add(-time.Hour),
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
}

func TestHMACRefreshToken(t *testing.T) {
	token, signature, err := hmacshaStrategy.GenerateRefreshToken(nil, &hmacValidCase)
	assert.NoError(t, err)
	assert.Equal(t, strings.Split(token, ".")[1], signature)

	validate := hmacshaStrategy.Enigma.Signature(token)
	err = hmacshaStrategy.ValidateRefreshToken(nil, &hmacValidCase, token)
	assert.NoError(t, err)
	assert.Equal(t, signature, validate)
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
}
