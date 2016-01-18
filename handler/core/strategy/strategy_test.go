package strategy

import (
	"strings"
	"testing"
	"time"

	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/enigma"
	"github.com/ory-am/fosite/enigma/jwthelper"
	"github.com/stretchr/testify/assert"
)

var s = HMACSHAStrategy{
	Enigma: &enigma.HMACSHAEnigma{GlobalSecret: []byte("foobarfoobarfoobarfoobar")},
}

var j = &JWTStrategy{
	Enigma: &enigma.JWTEnigma{
		PrivateKey: []byte(enigma.TestCertificates[0][1]),
		PublicKey:  []byte(enigma.TestCertificates[1][1]),
	},
}

var claims, claimsErr = jwthelper.NewClaimsContext("fosite", "peter", "group0",
	time.Now().Add(time.Hour), time.Now(), time.Now(), make(map[string]interface{}))

var r = &fosite.Request{
	Client: &client.SecureClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},

	Session: &JWTSession{
		JWTClaimsCtx: *claims,
		JWTHeaders:   make(map[string]interface{}),
	},
}

func TestAccessToken(t *testing.T) {
	// HMAC
	token, signature, err := s.GenerateAccessToken(nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[1], signature)

	validate, err := s.ValidateAccessToken(token, nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)

	// JWT

	// Valid
	token, signature, err = j.GenerateAccessToken(nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[2], signature)

	validate, err = j.ValidateAccessToken(token, nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)

	// Invalid
	oldSession := r.Session
	r.Session = nil
	token, signature, err = j.GenerateAccessToken(nil, nil, r)
	assert.NotNil(t, err, "%s", err)
	r.Session = oldSession

	// Invalid
	oldClaims := r.Session.(*JWTSession).JWTClaimsCtx
	r.Session.(*JWTSession).JWTClaimsCtx = nil
	token, signature, err = j.GenerateAccessToken(nil, nil, r)
	assert.NotNil(t, err, "%s", err)
	r.Session.(*JWTSession).JWTClaimsCtx = oldClaims
}

func TestRefreshToken(t *testing.T) {
	// HMAC
	token, signature, err := s.GenerateRefreshToken(nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[1], signature)

	validate, err := s.ValidateRefreshToken(token, nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)

	// JWT

	// Valid
	token, signature, err = j.GenerateRefreshToken(nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[2], signature)

	validate, err = j.ValidateRefreshToken(token, nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)

	// Invalid
	oldSession := r.Session
	r.Session = nil
	token, signature, err = j.GenerateRefreshToken(nil, nil, r)
	assert.NotNil(t, err, "%s", err)
	r.Session = oldSession

	// Invalid
	oldClaims := r.Session.(*JWTSession).JWTClaimsCtx
	r.Session.(*JWTSession).JWTClaimsCtx = nil
	token, signature, err = j.GenerateRefreshToken(nil, nil, r)
	assert.NotNil(t, err, "%s", err)
	r.Session.(*JWTSession).JWTClaimsCtx = oldClaims
}

func TestGenerateAuthorizeCode(t *testing.T) {
	// HMAC
	token, signature, err := s.GenerateAuthorizeCode(nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[1], signature)

	validate, err := s.ValidateAuthorizeCode(token, nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)

	// JWT

	// Valid
	token, signature, err = j.GenerateAuthorizeCode(nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[2], signature)

	validate, err = j.ValidateAuthorizeCode(token, nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)

	// Invalid
	oldSession := r.Session
	r.Session = nil
	token, signature, err = j.GenerateAuthorizeCode(nil, nil, r)
	assert.NotNil(t, err, "%s", err)
	r.Session = oldSession

	// Invalid
	oldClaims := r.Session.(*JWTSession).JWTClaimsCtx
	r.Session.(*JWTSession).JWTClaimsCtx = nil
	token, signature, err = j.GenerateAuthorizeCode(nil, nil, r)
	assert.NotNil(t, err, "%s", err)
	r.Session.(*JWTSession).JWTClaimsCtx = oldClaims
}
