package generator

import (
	"github.com/ory-am/fosite/hash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGenerate(t *testing.T) {
	cg := CryptoGenerator{Hasher: &hash.BCrypt{}}
	code, err := cg.Generate()
	require.Nil(t, err, "%s", err)
	require.NotNil(t, code)

	err = cg.ValidateSignature(code)
	require.Nil(t, err, "%s", err)
}

func TestValidateSignatureRejects(t *testing.T) {
	var err error
	cg := CryptoGenerator{
		Hasher: &hash.BCrypt{},
	}
	token := new(Token)
	for _, c := range []string{
		"",
		" ",
		"foo.bar",
		"foo.",
		".foo",
	} {
		token.FromString(c)
		err = cg.ValidateSignature(token)
		assert.NotNil(t, err, "%s", err)
	}
}
