package fosite

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthorizeResponse(t *testing.T) {
	ar := &AuthorizeResponse{
		Header:   http.Header{},
		Query:    url.Values{},
		Fragment: url.Values{},
		ID:       "foo",
	}
	ar.AddFragment("foo", "bar")
	ar.AddQuery("foo", "baz")
	ar.AddHeader("foo", "foo")

	assert.Equal(t, "bar", ar.GetFragment().Get("foo"))
	assert.Equal(t, "baz", ar.GetQuery().Get("foo"))
	assert.Equal(t, "foo", ar.GetHeader().Get("foo"))

	assert.Equal(t, ar.ID, ar.GetID())
	ar.SetID("bar")
	assert.Equal(t, "bar", ar.GetID())
}
