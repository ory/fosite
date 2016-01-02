package fosite

import (
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"
)

func TestGetRedirectURIAgainstRFC6749Section3(t *testing.T) {
	cf := &Config{}
	for _, c := range []struct {
		in       string
		isError  bool
		expected string
	}{
		{in: "", isError: true},
	} {
		values := url.Values{}
		values.Set("redirect_uri", c.in)
		res, err := cf.GetRedirectURI(values)
		assert.Equal(t, c.isError, err != nil)
		if err == nil {
			assert.Equal(t, c.expected, res)
		}
	}
}
