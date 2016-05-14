package fosite

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultClient(t *testing.T) {
	sc := &DefaultClient{
		ID:            "1",
		Secret:        []byte("foobar-"),
		RedirectURIs:  []string{"foo", "bar"},
		ResponseTypes: []string{"foo", "bar"},
		GrantTypes:    []string{"foo", "bar"},
	}
	assert.Equal(t, sc.ID, sc.GetID())
	assert.Equal(t, sc.RedirectURIs, sc.GetRedirectURIs())
	assert.Equal(t, sc.Secret, sc.GetHashedSecret())
	assert.EqualValues(t, sc.ResponseTypes, sc.GetResponseTypes())
	assert.EqualValues(t, sc.GrantTypes, sc.GetGrantTypes())

	assert.False(t, sc.GetGrantedScopes().Fulfill("foo.bar.baz"))
	assert.False(t, sc.GetGrantedScopes().Fulfill("foo.bar"))
	assert.False(t, sc.GetGrantedScopes().Fulfill("foo"))

	sc.GrantedScopes = []string{"foo.bar", "bar.baz"}
	assert.True(t, sc.GetGrantedScopes().Fulfill("foo.bar.baz"))
	assert.True(t, sc.GetGrantedScopes().Fulfill("foo.bar"))
	assert.False(t, sc.GetGrantedScopes().Fulfill("foo"))

	assert.True(t, sc.GetGrantedScopes().Fulfill("bar.baz"))
	assert.True(t, sc.GetGrantedScopes().Fulfill("bar.baz.zad"))
	assert.False(t, sc.GetGrantedScopes().Fulfill("bar"))

	assert.False(t, sc.GetGrantedScopes().Fulfill("baz"))

	sc.GrantTypes = []string{}
	sc.ResponseTypes = []string{}
	assert.Equal(t, "code", sc.GetResponseTypes()[0])
	assert.Equal(t, "authorization_code", sc.GetGrantTypes()[0])
}

func TestDefaultScope(t *testing.T) {

}