package client

import "testing"
import (
	"github.com/ory-am/fosite/hash"
	"github.com/stretchr/testify/assert"
)

func TestSecureClient(t *testing.T) {
	hasher := &hash.BCrypt{WorkFactor: 5}
	secret, _ := hasher.Hash([]byte("foo"))
	sc := &SecureClient{
		ID:           "1",
		Secret:       secret,
		RedirectURIs: []string{"foo", "bar"},
		Hasher:       hasher,
	}
	assert.Equal(t, sc.ID, sc.GetID())
	assert.Equal(t, sc.RedirectURIs, sc.GetRedirectURIs())
	assert.True(t, sc.CompareSecretWith([]byte("foo")))
	assert.False(t, sc.CompareSecretWith([]byte("bar")))
	assert.Equal(t, sc.Secret, sc.GetHashedSecret())
}
