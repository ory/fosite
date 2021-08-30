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

package jwt_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "github.com/ory/fosite/token/jwt"
)

var jwtClaims = &JWTClaims{
	Subject:   "peter",
	IssuedAt:  time.Now().UTC().Round(time.Second),
	Issuer:    "fosite",
	NotBefore: time.Now().UTC().Round(time.Second),
	Audience:  []string{"tests"},
	ExpiresAt: time.Now().UTC().Add(time.Hour).Round(time.Second),
	JTI:       "abcdef",
	Scope:     []string{"email", "offline"},
	Extra: map[string]interface{}{
		"foo": "bar",
		"baz": "bar",
	},
	ScopeField: JWTScopeFieldList,
}

var jwtClaimsMap = map[string]interface{}{
	"sub": jwtClaims.Subject,
	"iat": jwtClaims.IssuedAt.Unix(),
	"iss": jwtClaims.Issuer,
	"nbf": jwtClaims.NotBefore.Unix(),
	"aud": jwtClaims.Audience,
	"exp": jwtClaims.ExpiresAt.Unix(),
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
	assert.Nil(t, (&JWTClaims{NotBefore: time.Now().UTC().Add(-time.Hour)}).
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

func TestScopeFieldString(t *testing.T) {
	jwtClaimsWithString := jwtClaims.WithScopeField(JWTScopeFieldString)
	// Making a copy of jwtClaimsMap.
	jwtClaimsMapWithString := jwtClaims.ToMap()
	delete(jwtClaimsMapWithString, "scp")
	jwtClaimsMapWithString["scope"] = "email offline"
	assert.Equal(t, jwtClaimsMapWithString, map[string]interface{}(jwtClaimsWithString.ToMapClaims()))
	var claims JWTClaims
	claims.FromMap(jwtClaimsMapWithString)
	assert.Equal(t, jwtClaimsWithString, &claims)
}

func TestScopeFieldBoth(t *testing.T) {
	jwtClaimsWithBoth := jwtClaims.WithScopeField(JWTScopeFieldBoth)
	// Making a copy of jwtClaimsMap
	jwtClaimsMapWithBoth := jwtClaims.ToMap()
	jwtClaimsMapWithBoth["scope"] = "email offline"
	assert.Equal(t, jwtClaimsMapWithBoth, map[string]interface{}(jwtClaimsWithBoth.ToMapClaims()))
	var claims JWTClaims
	claims.FromMap(jwtClaimsMapWithBoth)
	assert.Equal(t, jwtClaimsWithBoth, &claims)
}
