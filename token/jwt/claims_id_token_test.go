package jwt_test

import (
	"testing"
	"time"

	. "github.com/ory-am/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
)

var idTokenClaims = &IDTokenClaims{
	Subject:   "peter",
	IssuedAt:  time.Now().Round(time.Second),
	Issuer:    "fosite",
	Audience:  "tests",
	ExpiresAt: time.Now().Add(time.Hour).Round(time.Second),
	Extra: map[string]interface{}{
		"foo": "bar",
		"baz": "bar",
	},
}

func TestIDTokenClaimsToMapSetsID(t *testing.T) {
	assert.NotEmpty(t, (&JWTClaims{}).ToMap()["jti"])
}

func TestIDTokenAssert(t *testing.T) {
	assert.False(t, (&JWTClaims{ExpiresAt: time.Now().Add(time.Hour)}).IsExpired())
	assert.True(t, (&JWTClaims{ExpiresAt: time.Now().Add(-time.Hour)}).IsExpired())
	assert.True(t, (&JWTClaims{NotBefore: time.Now().Add(time.Hour)}).IsNotYetValid())
	assert.False(t, (&JWTClaims{NotBefore: time.Now().Add(-time.Hour)}).IsNotYetValid())
}

func TestIDTokenClaimsToMap(t *testing.T) {
	assert.Equal(t, map[string]interface{}{
		"sub": idTokenClaims.Subject,
		"iat": idTokenClaims.IssuedAt.Unix(),
		"iss": idTokenClaims.Issuer,
		"aud": idTokenClaims.Audience,
		"nonce": idTokenClaims.Nonce,
		"exp": idTokenClaims.ExpiresAt.Unix(),
		"foo": idTokenClaims.Extra["foo"],
		"baz": idTokenClaims.Extra["baz"],
		"at_hash": idTokenClaims.AccessTokenHash,
		"c_hash": idTokenClaims.CodeHash,
		"auth_time": idTokenClaims.AuthTime.Unix(),
	}, idTokenClaims.ToMap())
}
