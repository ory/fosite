package jwt_test

import (
	"testing"
	"time"

	. "github.com/ory-am/fosite/enigma/jwt"
	"github.com/stretchr/testify/assert"
)

var claims = &JWTClaims{
	Subject:   "peter",
	IssuedAt:  time.Now().Round(time.Second),
	Issuer:    "fosite",
	NotBefore: time.Now().Round(time.Second),
	Audience:  "tests",
	ExpiresAt: time.Now().Add(time.Hour).Round(time.Second),
	JTI:       "abcdef",
	Extra: map[string]interface{}{
		"foo": "bar",
		"baz": "bar",
	},
}

func TestClaimsToMapSetsID(t *testing.T) {
	assert.NotEmpty(t, (&JWTClaims{}).ToMap()["jti"])
}

func TestClaimsToFromMap(t *testing.T) {
	fromMap := JWTClaimsFromMap(claims.ToMap())
	assert.Equal(t, claims, fromMap)
}

func TestAssert(t *testing.T) {
	assert.False(t, (&JWTClaims{ExpiresAt: time.Now().Add(time.Hour)}).IsExpired())
	assert.True(t, (&JWTClaims{ExpiresAt: time.Now().Add(-time.Hour)}).IsExpired())
	assert.True(t, (&JWTClaims{NotBefore: time.Now().Add(time.Hour)}).IsNotYetValid())
	assert.False(t, (&JWTClaims{NotBefore: time.Now().Add(-time.Hour)}).IsNotYetValid())
}

func TestClaimsToMap(t *testing.T) {
	assert.Equal(t, map[string]interface{}{
		"sub": claims.Subject,
		"iat": claims.IssuedAt.Unix(),
		"iss": claims.Issuer,
		"nbf": claims.NotBefore.Unix(),
		"aud": claims.Audience,
		"exp": claims.ExpiresAt.Unix(),
		"jti": claims.JTI,
		"foo": claims.Extra["foo"],
		"baz": claims.Extra["baz"],
	}, claims.ToMap())
}
