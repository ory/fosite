package strategy

import (
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/enigma"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

var s = HMACSHAStrategy{
	Enigma: &enigma.HMACSHAEnigma{GlobalSecret: []byte("foobarfoobarfoobarfoobar")},
}

var r = &fosite.Request{
	Client: &client.SecureClient{
		Secret: []byte("foobarfoobarfoobarfoobar"),
	},
}

func TestAccessToken(t *testing.T) {
	token, signature, err := s.GenerateAccessToken(nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[1], signature)

	validate, err := s.ValidateAccessToken(token, nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)
}

func TestRefreshToken(t *testing.T) {
	token, signature, err := s.GenerateRefreshToken(nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[1], signature)

	validate, err := s.ValidateRefreshToken(token, nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)
}

func TestGenerateAuthorizeCode(t *testing.T) {
	token, signature, err := s.GenerateAuthorizeCode(nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, strings.Split(token, ".")[1], signature)

	validate, err := s.ValidateAuthorizeCode(token, nil, nil, r)
	assert.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validate)
}
