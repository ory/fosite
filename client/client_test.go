package client

import "testing"
import (
	"github.com/stretchr/testify/assert"
)

func TestSecureClient(t *testing.T) {
	sc := &SecureClient{
		ID:           "1",
		Secret:       []byte("foobar-"),
		RedirectURIs: []string{"foo", "bar"},
	}
	assert.Equal(t, sc.ID, sc.GetID())
	assert.Equal(t, sc.RedirectURIs, sc.GetRedirectURIs())
	assert.Equal(t, sc.Secret, sc.GetHashedSecret())
}
