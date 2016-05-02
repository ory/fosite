package strategy

import (
	"strings"
	"testing"
	"time"

	"github.com/ory-am/fosite"
	hmac "github.com/ory-am/fosite/token/hmac"
	jwt "github.com/ory-am/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
)

var s = HMACSHAStrategy{
	Enigma: &hmac.HMACStrategy{GlobalSecret: []byte("foobarfoobarfoobarfoobar")},
}

var j = &RS256JWTStrategy{
	RS256JWTStrategy: &jwt.RS256JWTStrategy{
		PrivateKey: []byte(jwt.TestCertificates[0][1]),
		PublicKey:  []byte(jwt.TestCertificates[1][1]),
	},
}

var claims = &jwt.JWTClaims{
	Issuer:    "fosite",
	Subject:   "peter",
	Audience:  "group0",
	ExpiresAt: time.Now().Add(time.Hour),
	IssuedAt:  time.Now(),
	NotBefore: time.Now(),
	Extra:     make(map[string]interface{}),
}

var r = &fosite.Request{
	Client: &fosite.DefaultClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},

	Session: &JWTSession{
		JWTClaims: claims,
		JWTHeader: &jwt.Header{
			Extra: make(map[string]interface{}),
		},
	},
}

func TestAccessToken(t *testing.T) {
	// HMAC
	token, signature, err := s.GenerateAccessToken(nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[1], signature)

	validate, err := s.ValidateAccessToken(nil, r, token)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)

	// JWT

	// Valid
	token, signature, err = j.GenerateAccessToken(nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[2], signature)

	validate, err = j.ValidateAccessToken(nil, r, token)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)

	// Invalid
	oldSession := r.Session
	r.Session = nil
	token, signature, err = j.GenerateAccessToken(nil, r)
	assert.NotNil(t, err, "%s", err)
	r.Session = oldSession

	// Invalid
	oldClaims := r.Session.(*JWTSession).JWTClaims
	r.Session.(*JWTSession).JWTClaims = nil
	token, signature, err = j.GenerateAccessToken(nil, r)
	assert.NotNil(t, err, "%s", err)
	r.Session.(*JWTSession).JWTClaims = oldClaims
}

func TestRefreshToken(t *testing.T) {
	// HMAC
	token, signature, err := s.GenerateRefreshToken(nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[1], signature)

	validate, err := s.ValidateRefreshToken(nil, r, token)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)

	// JWT

	// Valid
	token, signature, err = j.GenerateRefreshToken(nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[2], signature)

	validate, err = j.ValidateRefreshToken(nil, r, token)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)

	// Invalid
	oldSession := r.Session
	r.Session = nil
	token, signature, err = j.GenerateRefreshToken(nil, r)
	assert.NotNil(t, err, "%s", err)
	r.Session = oldSession

	// Invalid
	oldClaims := r.Session.(*JWTSession).JWTClaims
	r.Session.(*JWTSession).JWTClaims = nil
	token, signature, err = j.GenerateRefreshToken(nil, r)
	assert.NotNil(t, err, "%s", err)
	r.Session.(*JWTSession).JWTClaims = oldClaims
}

func TestGenerateAuthorizeCode(t *testing.T) {
	// HMAC
	token, signature, err := s.GenerateAuthorizeCode(nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[1], signature)

	validate, err := s.ValidateAuthorizeCode(nil, r, token)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)

	// JWT

	// Valid
	token, signature, err = j.GenerateAuthorizeCode(nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[2], signature)

	validate, err = j.ValidateAuthorizeCode(nil, r, token)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)

	// Invalid
	oldSession := r.Session
	r.Session = nil
	token, signature, err = j.GenerateAuthorizeCode(nil, r)
	assert.NotNil(t, err, "%s", err)
	r.Session = oldSession

	// Invalid
	oldClaims := r.Session.(*JWTSession).JWTClaims
	r.Session.(*JWTSession).JWTClaims = nil
	token, signature, err = j.GenerateAuthorizeCode(nil, r)
	assert.NotNil(t, err, "%s", err)
	r.Session.(*JWTSession).JWTClaims = oldClaims
}
