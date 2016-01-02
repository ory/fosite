package generator

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTokenToString(t *testing.T) {
	ac := &Token{
		Key:       "foo",
		Signature: "bar",
	}
	assert.Equal(t, "foo.bar", ac.String())
}
func TestTokenFromString(t *testing.T) {
	ac := new(Token)
	for _, c := range [][]string{
		{"foo.bar", "foo", "bar"},
		{"foo.", "", ""},
		{"foo", "", ""},
		{".bar", "", ""},
	} {
		ac.FromString(c[0])
		assert.Equal(t, c[1], ac.Key)
		assert.Equal(t, c[2], ac.Signature)
	}
}
