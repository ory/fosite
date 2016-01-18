package enigma

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGenerateFailsWithShortCredentials(t *testing.T) {
	cg := HMACSHAEnigma{GlobalSecret: []byte("foo")}
	challenge, signature, err := cg.Generate([]byte("bar"))
	require.NotNil(t, err, "%s", err)
	require.Empty(t, challenge)
	require.Empty(t, signature)

	cg.GlobalSecret = []byte("12345678901234567890")
	challenge, signature, err = cg.Generate([]byte("bar"))
	require.NotNil(t, err, "%s", err)
	require.Empty(t, challenge)
	require.Empty(t, signature)

	cg.GlobalSecret = []byte("bar")
	challenge, signature, err = cg.Generate([]byte("12345678901234567890"))
	require.NotNil(t, err, "%s", err)
	require.Empty(t, challenge)
	require.Empty(t, signature)
}

func TestGenerate(t *testing.T) {
	cg := HMACSHAEnigma{
		GlobalSecret: []byte("12345678901234567890"),
	}

	token, signature, err := cg.Generate([]byte("09876543210987654321"))
	require.Nil(t, err, "%s", err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, signature)
	t.Logf("Token: %s\n Signature: %s", token, signature)

	validateSignature, err := cg.Validate([]byte("09876543210987654321"), token)
	require.Nil(t, err, "%s", err)
	assert.Equal(t, signature, validateSignature)

	_, err = cg.Validate([]byte("bar"), token)
	require.NotNil(t, err, "%s", err)

	_, err = cg.Validate([]byte("baz"), token)
	require.NotNil(t, err, "%s", err)

	cg.GlobalSecret = []byte("baz")
	_, err = cg.Validate([]byte("bar"), token)
	require.NotNil(t, err, "%s", err)
}

func TestValidateSignatureRejects(t *testing.T) {
	var err error
	cg := HMACSHAEnigma{
		GlobalSecret: []byte("12345678901234567890"),
	}
	for k, c := range []string{
		"",
		" ",
		"foo.bar",
		"foo.",
		".foo",
	} {
		_, err = cg.Validate([]byte("09876543210987654321"), c)
		assert.NotNil(t, err, "%s", err)
		t.Logf("Passed test case %d", k)
	}
}
