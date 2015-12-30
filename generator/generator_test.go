package generator

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAuthorizeCodeToString(t *testing.T) {
	ac := &AuthorizeCode{
		Key:       "foo",
		Signature: "bar",
	}
	assert.Equal(t, "foo.bar", ac.String())
}
func TestAuthorizeCodeFromString(t *testing.T) {
	ac := new(AuthorizeCode)
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
