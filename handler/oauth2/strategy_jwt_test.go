package oauth2

import (
	"strings"
	"testing"
	"time"

	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/internal"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
)

var j = &RS256JWTStrategy{
	RS256JWTStrategy: &jwt.RS256JWTStrategy{
		PrivateKey: internal.MustRSAKey(),
	},
}

var jwtValidCase = fosite.Request{
	Client: &fosite.DefaultClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},
	Session: &JWTSession{
		JWTClaims: &jwt.JWTClaims{
			Issuer:    "fosite",
			Subject:   "peter",
			Audience:  "group0",
			ExpiresAt: time.Now().Add(time.Hour),
			IssuedAt:  time.Now(),
			NotBefore: time.Now(),
			Extra:     make(map[string]interface{}),
		},
		JWTHeader: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	},
}

var jwtExpiredCase = fosite.Request{
	Client: &fosite.DefaultClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},
	Session: &JWTSession{
		JWTClaims: &jwt.JWTClaims{
			Issuer:    "fosite",
			Subject:   "peter",
			Audience:  "group0",
			ExpiresAt: time.Now().Add(-time.Hour),
			IssuedAt:  time.Now(),
			NotBefore: time.Now(),
			Extra:     make(map[string]interface{}),
		},
		JWTHeader: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	},
}

func TestAccessToken(t *testing.T) {
	for _, c := range []struct {
		r    fosite.Request
		pass bool
	}{
		{
			r:    jwtValidCase,
			pass: true,
		},
		{
			r:    jwtExpiredCase,
			pass: false,
		},
	} {
		token, signature, err := j.GenerateAccessToken(nil, &c.r)
		assert.Nil(t, err, "%s", err)
		assert.Equal(t, strings.Split(token, ".")[2], signature)

		validate := j.signature(token)
		err = j.ValidateAccessToken(nil, &c.r, token)
		if c.pass {
			assert.Nil(t, err, "%s", err)
			assert.Equal(t, signature, validate)
		} else {
			assert.NotNil(t, err, "%s", err)
		}
	}
}

func TestRefreshToken(t *testing.T) {
	token, signature, err := j.GenerateRefreshToken(nil, &jwtValidCase)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[2], signature)

	validate := j.signature(token)
	err = j.ValidateRefreshToken(nil, &jwtValidCase, token)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)
}

func TestGenerateAuthorizeCode(t *testing.T) {
	for _, c := range []struct {
		r    fosite.Request
		pass bool
	}{
		{
			r:    jwtValidCase,
			pass: true,
		},
		{
			r:    jwtExpiredCase,
			pass: false,
		},
	} {
		token, signature, err := j.GenerateAuthorizeCode(nil, &c.r)
		assert.Nil(t, err, "%s", err)
		assert.Equal(t, strings.Split(token, ".")[2], signature)

		validate := j.signature(token)
		err = j.ValidateAuthorizeCode(nil, &c.r, token)
		if c.pass {
			assert.Nil(t, err, "%s", err)
			assert.Equal(t, signature, validate)
		} else {
			assert.NotNil(t, err, "%s", err)
		}
	}
}
