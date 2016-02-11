package jwt_test

import (
	"testing"
	"time"

	. "github.com/ory-am/fosite/enigma/jwt"
	"github.com/stretchr/testify/assert"
)

var claims = &Claims{
	Subject:   "peter",
	IssuedAt:  time.Now().Round(time.Second),
	Issuer:    "fosite",
	NotValidBefore: time.Now().Round(time.Second),
	Audience:  "tests",
	ExpiresAt: time.Now().Add(time.Hour).Round(time.Second),
	ID:        "abcdef",
	Extra: map[string]interface{}{
		"foo": "bar",
		"baz": "bar",
	},
}

func TestClaimsToMapSetsID(t *testing.T) {
	assert.NotEmpty(t, (&Claims{}).ToMap()["jti"])
}

func TestClaimsToFromMap(t *testing.T) {
	fromMap := ClaimsFromMap(claims.ToMap())
	assert.Equal(t, claims, fromMap)
}

func TestAssert(t *testing.T) {
	assert.False(t, (&Claims{ExpiresAt: time.Now().Add(time.Hour)}).AssertExpired())
	assert.True(t, (&Claims{ExpiresAt: time.Now().Add(-time.Hour)}).AssertExpired())
	assert.True(t, (&Claims{NotValidBefore: time.Now().Add(time.Hour)}).AssertNotYetValid())
	assert.False(t, (&Claims{NotValidBefore: time.Now().Add(-time.Hour)}).AssertNotYetValid())
}

func TestClaimsToMap(t *testing.T) {
	assert.Equal(t, map[string]interface{}{
		"sub": claims.Subject,
		"iat": claims.IssuedAt.Unix(),
		"iss": claims.Issuer,
		"nbf": claims.NotValidBefore.Unix(),
		"aud": claims.Audience,
		"exp": claims.ExpiresAt.Unix(),
		"jti": claims.ID,
		"foo": claims.Extra["foo"],
		"baz": claims.Extra["baz"],
	}, claims.ToMap())
}
