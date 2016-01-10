package fosite

import (
	"github.com/ory-am/fosite/client"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAccessRequest(t *testing.T) {
	ar := NewAccessRequest()
	ar.GrantType = "foobar"
	ar.Client = &client.SecureClient{}
	assert.NotNil(t, ar.GetRequestedAt())
	assert.Equal(t, ar.GrantType, ar.GetGrantType())
	assert.Equal(t, ar.Client, ar.GetClient())
}
