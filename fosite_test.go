package fosite_test

import (
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/authorize/explicit"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAuthorizeEndpointHandlers(t *testing.T) {
	h := &explicit.AuthorizeExplicitEndpointHandler{}
	hs := AuthorizeEndpointHandlers{}
	hs.Add("k", h)
	assert.Len(t, hs, 1)
	assert.Equal(t, hs["k"], h)
}

func TestTokenEndpointHandlers(t *testing.T) {
	h := &explicit.AuthorizeExplicitEndpointHandler{}
	hs := TokenEndpointHandlers{}
	hs.Add("k", h)
	assert.Len(t, hs, 1)
	assert.Equal(t, hs["k"], h)
}
