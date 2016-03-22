package fosite

import (
	"testing"

	"github.com/ory-am/fosite/client"
	"github.com/stretchr/testify/assert"
)

func TestAccessRequest(t *testing.T) {
	ar := NewAccessRequest(nil)
	ar.GrantTypes = Arguments{"foobar"}
	ar.Client = &client.SecureClient{}
	ar.GrantScope("foo")
	assert.True(t, ar.GetGrantedScopes().Has("foo"))
	assert.NotNil(t, ar.GetRequestedAt())
	assert.Equal(t, ar.GrantTypes, ar.GetGrantTypes())
	assert.Equal(t, ar.Client, ar.GetClient())
}
