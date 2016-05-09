package jwt_test

import (
	"testing"
	"time"

	. "github.com/ory-am/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
)

var jwtClaims = &JWTClaims{
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

func TestClaimAddGetString(t *testing.T) {
	jwtClaims.Add("foo", "bar")
	assert.Equal(t, "bar", jwtClaims.Get("foo"))
}

func TestClaimsToMapSetsID(t *testing.T) {
	assert.NotEmpty(t, (&JWTClaims{}).ToMap()["jti"])
}

func TestClaimsToFromMap(t *testing.T) {
	fromMap := JWTClaimsFromMap(jwtClaims.ToMap())
	assert.Equal(t, jwtClaims, fromMap)
}

func TestAssert(t *testing.T) {
	assert.False(t, (&JWTClaims{ExpiresAt: time.Now().Add(time.Hour)}).IsExpired())
	assert.True(t, (&JWTClaims{ExpiresAt: time.Now().Add(-time.Hour)}).IsExpired())
	assert.True(t, (&JWTClaims{NotBefore: time.Now().Add(time.Hour)}).IsNotYetValid())
	assert.False(t, (&JWTClaims{NotBefore: time.Now().Add(-time.Hour)}).IsNotYetValid())
}

func TestClaimsToMap(t *testing.T) {
	assert.Equal(t, map[string]interface{}{
		"sub": jwtClaims.Subject,
		"iat": jwtClaims.IssuedAt.Unix(),
		"iss": jwtClaims.Issuer,
		"nbf": jwtClaims.NotBefore.Unix(),
		"aud": jwtClaims.Audience,
		"exp": jwtClaims.ExpiresAt.Unix(),
		"jti": jwtClaims.JTI,
		"foo": jwtClaims.Extra["foo"],
		"baz": jwtClaims.Extra["baz"],
	}, jwtClaims.ToMap())
}
