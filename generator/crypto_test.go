package generator

import (
	"testing"
	"github.com/ory-am/fosite/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAuthorizeCode(t *testing.T) {
	cg := CryptoGenerator{
		Hasher: &hash.BCrypt{},
	}
	code, err := cg.GenerateAuthorizeCode()
	require.Nil(t, err, "%s", err)
	assert.NotEmpty(t, code)
	validCode, err := cg.ValidateAuthorizeCode(code.String())
	require.Nil(t, err, "%s", err)
	assert.Equal(t, validCode.Key, code.Key)
	assert.Equal(t, validCode.Signature, code.Signature)
}

func TestValidateAuthorizeCode(t *testing.T){
	var err error
	cg := CryptoGenerator{
		Hasher: &hash.BCrypt{},
	}
	for _, c := range []string {
		"",
		" ",
		"foo.bar",
		"foo.",
		".foo",
	} {
		_, err = cg.ValidateAuthorizeCode(c)
		assert.NotNil(t, err)
	}
}