package strategy

import (
	"testing"

	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/token/jwt"
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
		Claims:  &jwt.IDTokenClaims{},
		Headers: &jwt.Header{},
	})
	token, err := j.GenerateIDToken(nil, nil, req, map[string]interface{}{"acr": "foo"})
	assert.Nil(t, err)
	assert.NotEmpty(t, token)
}
