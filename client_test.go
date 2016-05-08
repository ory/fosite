package fosite

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultClient(t *testing.T) {
	sc := &DefaultClient{
		ID:           "1",
		Secret:       []byte("foobar-"),
		RedirectURIs: []string{"foo", "bar"},
		ResponseTypes:[]string{"foo", "bar"},
		GrantTypes:[]string{"foo", "bar"},
	}
	assert.Equal(t, sc.ID, sc.GetID())
	assert.Equal(t, sc.RedirectURIs, sc.GetRedirectURIs())
	assert.Equal(t, sc.Secret, sc.GetHashedSecret())
	assert.EqualValues(t, sc.ResponseTypes, sc.GetResponseTypes())
	assert.EqualValues(t, sc.GrantTypes, sc.GetGrantTypes())

	sc.GrantTypes = []string{}
	sc.ResponseTypes = []string{}
	assert.Equal(t, "code", sc.GetResponseTypes()[0])
	assert.Equal(t, "authorization_code", sc.GetGrantTypes()[0])
}
