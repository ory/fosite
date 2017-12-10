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

package jwt_test

import (
	"testing"
	"time"

	. "github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
)

var jwtClaims = &JWTClaims{
	Subject:   "peter",
	IssuedAt:  time.Now().UTC().Round(time.Second),
	Issuer:    "fosite",
	NotBefore: time.Now().UTC().Round(time.Second),
	Audience:  "tests",
	ExpiresAt: time.Now().UTC().Add(time.Hour).Round(time.Second),
	JTI:       "abcdef",
	Scope:     []string{"email", "offline"},
	Extra: map[string]interface{}{
		"foo": "bar",
		"baz": "bar",
	},
}

var jwtClaimsMap = map[string]interface{}{
	"sub": jwtClaims.Subject,
	"iat": float64(jwtClaims.IssuedAt.Unix()),
	"iss": jwtClaims.Issuer,
	"nbf": float64(jwtClaims.NotBefore.Unix()),
	"aud": jwtClaims.Audience,
	"exp": float64(jwtClaims.ExpiresAt.Unix()),
	"jti": jwtClaims.JTI,
	"scp": []string{"email", "offline"},
	"foo": jwtClaims.Extra["foo"],
	"baz": jwtClaims.Extra["baz"],
}

func TestClaimAddGetString(t *testing.T) {
	jwtClaims.Add("foo", "bar")
	assert.Equal(t, "bar", jwtClaims.Get("foo"))
}

func TestClaimsToMapSetsID(t *testing.T) {
	assert.NotEmpty(t, (&JWTClaims{}).ToMap()["jti"])
}

func TestAssert(t *testing.T) {
	assert.Nil(t, (&JWTClaims{ExpiresAt: time.Now().UTC().Add(time.Hour)}).
		ToMapClaims().Valid())
	assert.NotNil(t, (&JWTClaims{ExpiresAt: time.Now().UTC().Add(-2 * time.Hour)}).
		ToMapClaims().Valid())
	assert.NotNil(t, (&JWTClaims{NotBefore: time.Now().UTC().Add(time.Hour)}).
		ToMapClaims().Valid())
	assert.NotNil(t, (&JWTClaims{NotBefore: time.Now().UTC().Add(-time.Hour)}).
		ToMapClaims().Valid())
	assert.Nil(t, (&JWTClaims{ExpiresAt: time.Now().UTC().Add(time.Hour),
		NotBefore: time.Now().UTC().Add(-time.Hour)}).ToMapClaims().Valid())
}

func TestClaimsToMap(t *testing.T) {
	assert.Equal(t, jwtClaimsMap, jwtClaims.ToMap())
}

func TestClaimsFromMap(t *testing.T) {
	var claims JWTClaims
	claims.FromMap(jwtClaimsMap)
	assert.Equal(t, jwtClaims, &claims)
}
