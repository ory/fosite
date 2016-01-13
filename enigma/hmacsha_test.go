package enigma

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGenerateFailsWithShortCredentials(t *testing.T) {
	cg := HMACSHAEnigma{
		GlobalSecret: []byte("foo"),
	}

	challenge, err := cg.GenerateChallenge([]byte("bar"))
	require.NotNil(t, err, "%s", err)
	require.Nil(t, challenge)

	cg.GlobalSecret = []byte("12345678901234567890")
	challenge, err = cg.GenerateChallenge([]byte("bar"))
	require.NotNil(t, err, "%s", err)
	require.Nil(t, challenge)

	cg.GlobalSecret = []byte("bar")
	challenge, err = cg.GenerateChallenge([]byte("12345678901234567890"))
	require.NotNil(t, err, "%s", err)
	require.Nil(t, challenge)
}

func TestGenerate(t *testing.T) {
	cg := HMACSHAEnigma{
		GlobalSecret: []byte("12345678901234567890"),
	}

	challenge, err := cg.GenerateChallenge([]byte("09876543210987654321"))
	require.Nil(t, err, "%s", err)
	require.NotNil(t, challenge)
	t.Logf("%s.%s", challenge.Key, challenge.Signature)

	err = cg.ValidateChallenge([]byte("09876543210987654321"), challenge)
	require.Nil(t, err, "%s", err)

	challenge.FromString(challenge.String())

	err = cg.ValidateChallenge([]byte("09876543210987654321"), challenge)
	require.Nil(t, err, "%s", err)

	err = cg.ValidateChallenge([]byte("bar"), challenge)
	require.NotNil(t, err, "%s", err)

	err = cg.ValidateChallenge([]byte("baz"), challenge)
	require.NotNil(t, err, "%s", err)

	cg.GlobalSecret = []byte("baz")
	err = cg.ValidateChallenge([]byte("bar"), challenge)
	require.NotNil(t, err, "%s", err)
}

func TestValidateSignatureRejects(t *testing.T) {
	var err error
	cg := HMACSHAEnigma{
		GlobalSecret: []byte("12345678901234567890"),
	}
	token := new(Challenge)
	for k, c := range []string{
		"",
		" ",
		"foo.bar",
		"foo.",
		".foo",
	} {
		token.FromString(c)
		err = cg.ValidateChallenge([]byte("09876543210987654321"), token)
		assert.NotNil(t, err, "%s", err)
		t.Logf("Passed test case %d", k)
	}
}
