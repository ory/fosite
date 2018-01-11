package pkce

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSha256Verfier(t *testing.T) {
	// Instanciate the verifier
	v := &s256Verifier{}
	require.NotNil(t, v)
	require.Equal(t, S256, v.String())

	for k, c := range []struct {
		given    string
		expected string
		valid    bool
	}{
		{
			given:    "12345678",
			expected: "73l8gRjwLftklgfdXT-MdiMEjJwGPVMsyVxe16iYpk8",
			valid:    true,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			valid := v.Compare(c.given, c.expected)
			assert.Equal(t, c.valid, valid, fmt.Sprintf("Should be as expected, result: %t, expected: %t", valid, c.valid))
		})
	}

}
