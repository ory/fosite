package enigma

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestChallengeToString(t *testing.T) {
	ac := &Challenge{
		Key:       "foo",
		Signature: "bar",
	}
	assert.Equal(t, "foo.bar", ac.String())
}

func TestChallengeFromString(t *testing.T) {
	ac := new(Challenge)
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
