package pkce

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlainVerfier(t *testing.T) {
	// Instanciate the verifier
	v := &plainVerifier{}
	require.NotNil(t, v)
	require.Equal(t, Plain, v.String())

	for k, c := range []struct {
		given    string
		expected string
		valid    bool
	}{
		{
			given:    "123456",
			expected: "123456",
			valid:    true,
		},
		{
			given:    "123456",
			expected: "12345",
			valid:    false,
		},
		{
			given:    "12345",
			expected: "123456",
			valid:    false,
		},
		{ // Useless test, but codeverifier is not size limited by the verifier
			given:    "",
			expected: "",
			valid:    true,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			valid := v.Compare(c.given, c.expected)
			assert.Equal(t, c.valid, valid, fmt.Sprintf("Should be as expected, result: %t, expected: %t", valid, c.valid))
		})
	}

}
