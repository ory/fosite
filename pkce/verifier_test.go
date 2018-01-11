package pkce

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifier(t *testing.T) {
	require.NotNil(t, GetVerifier(Plain))
	require.NotNil(t, GetVerifier(S256))
	require.Nil(t, GetVerifier("invalid-verifier-method"))
}

func TestVerifierRegistration(t *testing.T) {
	require.NotNil(t, GetVerifier(Plain))
	require.Panics(t, func() {
		RegisterVerifier(Plain, &plainVerifier{})
	})
}
