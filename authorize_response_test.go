package fosite

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
)

func TestAuthorizeResponse(t *testing.T) {
	ar := &AuthorizeResponse{
		Header:   http.Header{},
		Query:    url.Values{},
		Fragment: url.Values{},
	}
	ar.AddFragment("foo", "bar")
	ar.AddQuery("foo", "baz")
	ar.AddHeader("foo", "foo")

	assert.Equal(t, "bar", ar.GetFragment().Get("foo"))
	assert.Equal(t, "baz", ar.GetQuery().Get("foo"))
	assert.Equal(t, "foo", ar.GetHeader().Get("foo"))
}
