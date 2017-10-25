package hmac

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateFailsWithShortCredentials(t *testing.T) {
	cg := HMACStrategy{GlobalSecret: []byte("foo")}
	challenge, signature, err := cg.Generate()
	require.Error(t, err)
	require.Empty(t, challenge)
	require.Empty(t, signature)
}

func TestGenerate(t *testing.T) {
	cg := HMACStrategy{
		GlobalSecret: []byte("1234567890123456789012345678901234567890"),
	}

	token, signature, err := cg.Generate()
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, signature)
	t.Logf("Token: %s\n Signature: %s", token, signature)

	err = cg.Validate(token)
	require.NoError(t, err)

	validateSignature := cg.Signature(token)
	assert.Equal(t, signature, validateSignature)

	cg.GlobalSecret = []byte("baz")
	err = cg.Validate(token)
	require.Error(t, err)
}

func TestValidateSignatureRejects(t *testing.T) {
	var err error
	cg := HMACStrategy{
		GlobalSecret: []byte("1234567890123456789012345678901234567890"),
	}
	for k, c := range []string{
		"",
		" ",
		"foo.bar",
		"foo.",
		".foo",
	} {
		err = cg.Validate(c)
		assert.Error(t, err)
		t.Logf("Passed test case %d", k)
	}
}
