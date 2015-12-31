package fosite
import (
"net/url"
"testing"
	"github.com/stretchr/testify/assert"
)

func TestGetRedirectURIAgainstRFC6749Section3(t *testing.T) {
	cf := &Config{}
	for _ , c := range []struct{
		in       string
		isError  bool
		expected string
	} {
		{in: "", isError: true},
	} {
		values := url.Values{}
		values.Set("redirect_uri", c)
		res, err := cf.GetRedirectURI(values)
		assert.Equal(t, c.isError, err != nil)
		if err == nil {
			assert.Equal(t, c.expected, res)
		}
	}
}