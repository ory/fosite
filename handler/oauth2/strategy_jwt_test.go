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
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
)

var j = &RS256JWTStrategy{
	RS256JWTStrategy: &jwt.RS256JWTStrategy{
		PrivateKey: internal.MustRSAKey(),
	},
}

// returns a valid JWT type. The JWTClaims.ExpiresAt time is intentionally
// left empty to ensure it is pulled from the session's ExpiresAt map for
// the given fosite.TokenType.
var jwtValidCase = func(tokenType fosite.TokenType) *fosite.Request {
	return &fosite.Request{
		Client: &fosite.DefaultClient{
			Secret: []byte("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "fosite",
				Subject:   "peter",
				Audience:  "group0",
				IssuedAt:  time.Now().UTC(),
				NotBefore: time.Now().UTC(),
				Extra:     make(map[string]interface{}),
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
			ExpiresAt: map[fosite.TokenType]time.Time{
				tokenType: time.Now().UTC().Add(time.Hour),
			},
		},
	}
}

// returns an expired JWT type. The JWTClaims.ExpiresAt time is intentionally
// left empty to ensure it is pulled from the session's ExpiresAt map for
// the given fosite.TokenType.
var jwtExpiredCase = func(tokenType fosite.TokenType) *fosite.Request {
	return &fosite.Request{
		Client: &fosite.DefaultClient{
			Secret: []byte("foobarfoobarfoobarfoobar"),
		},
		Session: &JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "fosite",
				Subject:   "peter",
				Audience:  "group0",
				IssuedAt:  time.Now().UTC(),
				NotBefore: time.Now().UTC(),
				ExpiresAt: time.Now().UTC().Add(-time.Minute),
				Extra:     make(map[string]interface{}),
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
			ExpiresAt: map[fosite.TokenType]time.Time{
				tokenType: time.Now().UTC().Add(-time.Hour),
			},
		},
	}
}

func TestAccessToken(t *testing.T) {
	for k, c := range []struct {
		r    *fosite.Request
		pass bool
	}{
		{
			r:    jwtValidCase(fosite.AccessToken),
			pass: true,
		},
		{
			r:    jwtExpiredCase(fosite.AccessToken),
			pass: false,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			token, signature, err := j.GenerateAccessToken(nil, c.r)
			assert.NoError(t, err)
			assert.Equal(t, strings.Split(token, ".")[2], signature)

			validate := j.signature(token)
			err = j.ValidateAccessToken(nil, c.r, token)
			if c.pass {
				assert.NoError(t, err)
				assert.Equal(t, signature, validate)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
