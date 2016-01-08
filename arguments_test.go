package fosite

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestArgumentsHas(t *testing.T) {
	for k, c := range []struct {
		args   Arguments
		has    string
		expect bool
	}{
		{
			args:   Arguments{"foo", "bar"},
			has:    "foo",
			expect: true,
		},
		{
			args:   Arguments{"foo", "bar"},
			has:    "bar",
			expect: true,
		},
		{
			args:   Arguments{"foo", "bar"},
			has:    "baz",
			expect: false,
		},
		{
			args:   Arguments{},
			has:    "baz",
			expect: false,
		},
	} {
		assert.Equal(t, c.expect, c.args.Has(c.has), "%d", k)
		t.Logf("Passed test case %d", k)
	}
}
