package strategy

import (
	"testing"

	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/enigma/jwt"
	"github.com/stretchr/testify/assert"
)

var j = &JWTStrategy{
	Enigma: &jwt.Enigma{
		PrivateKey: []byte(jwt.TestCertificates[0][1]),
		PublicKey:  []byte(jwt.TestCertificates[1][1]),
	},
}

func TestGenerateIDToken(t *testing.T) {
	req := fosite.NewAccessRequest(&IDTokenSession{
		IDClaims: &jwt.Claims{},
		IDToken:  &jwt.Header{},
	})
	token, err := j.GenerateIDToken(nil, nil, req)
	assert.Nil(t, err)
	assert.NotEmpty(t, token)
}
