package oauth2

import (
	"strings"
	"testing"
	"time"

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
			fosite.AccessToken:   time.Now().Add(-time.Hour),
			fosite.AuthorizeCode: time.Now().Add(-time.Hour),
		},
	},
}

var hmacValidCase = fosite.Request{
	Client: &fosite.DefaultClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},
	Session: &fosite.DefaultSession{
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken:   time.Now().Add(time.Hour),
			fosite.AuthorizeCode: time.Now().Add(time.Hour),
		},
	},
}

func TestHMACAccessToken(t *testing.T) {
	for _, c := range []struct {
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
		token, signature, err := hmacshaStrategy.GenerateAccessToken(nil, &c.r)
		assert.Nil(t, err, "%s", err)
		assert.Equal(t, strings.Split(token, ".")[1], signature)

		err = hmacshaStrategy.ValidateAccessToken(nil, &c.r, token)
		if c.pass {
			assert.Nil(t, err, "%s", err)
			validate := hmacshaStrategy.Enigma.Signature(token)
			assert.Equal(t, signature, validate)
		} else {
			assert.NotNil(t, err, "%s", err)
		}
	}
}

func TestHMACRefreshToken(t *testing.T) {
	token, signature, err := hmacshaStrategy.GenerateRefreshToken(nil, &hmacValidCase)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[1], signature)

	validate := hmacshaStrategy.Enigma.Signature(token)
	err = hmacshaStrategy.ValidateRefreshToken(nil, &hmacValidCase, token)
	assert.Nil(t, err, "%s", err)
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
		token, signature, err := hmacshaStrategy.GenerateAuthorizeCode(nil, &c.r)
		assert.Nil(t, err, "%s", err)
		assert.Equal(t, strings.Split(token, ".")[1], signature)

		err = hmacshaStrategy.ValidateAuthorizeCode(nil, &c.r, token)
		if c.pass {
			assert.Nil(t, err, "%d: %s", k, err)
			validate := hmacshaStrategy.Enigma.Signature(token)
			assert.Equal(t, signature, validate)
		} else {
			assert.NotNil(t, err, "%d: %s", k, err)
		}
	}
}
