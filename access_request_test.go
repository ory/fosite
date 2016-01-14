package fosite

import (
	"github.com/ory-am/fosite/client"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAccessRequest(t *testing.T) {
	ar := &AccessRequest{}
	ar.GrantType = "foobar"
	ar.Client = &client.SecureClient{}
	ar.GrantScope("foo")
	assert.True(t, ar.GetGrantedScopes().Has("foo"))
	assert.NotNil(t, ar.GetRequestedAt())
	assert.Equal(t, ar.GrantType, ar.GetGrantType())
	assert.Equal(t, ar.Client, ar.GetClient())
}
