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

	assert.False(t, sc.GetGrantedScopes().Grants("foo.bar.baz"))
	assert.False(t, sc.GetGrantedScopes().Grants("foo.bar"))
	assert.False(t, sc.GetGrantedScopes().Grants("foo"))

	sc.GrantedScopes = []string{"foo.bar", "bar.baz", "baz.baz.1", "baz.baz.2", "baz.baz.3", "baz.baz.baz"}
	assert.True(t, sc.GetGrantedScopes().Grants("foo.bar.baz"))
	assert.True(t, sc.GetGrantedScopes().Grants("baz.baz.baz"))
	assert.True(t, sc.GetGrantedScopes().Grants("foo.bar"))
	assert.False(t, sc.GetGrantedScopes().Grants("foo"))

	assert.True(t, sc.GetGrantedScopes().Grants("bar.baz"))
	assert.True(t, sc.GetGrantedScopes().Grants("bar.baz.zad"))
	assert.False(t, sc.GetGrantedScopes().Grants("bar"))

	assert.False(t, sc.GetGrantedScopes().Grants("baz"))

	sc.GrantedScopes = []string{"fosite.keys.create", "fosite.keys.get", "fosite.keys.delete", "fosite.keys.update"}
	assert.True(t, sc.GetGrantedScopes().Grants("fosite.keys.delete"))
	assert.True(t, sc.GetGrantedScopes().Grants("fosite.keys.get"))
	assert.True(t, sc.GetGrantedScopes().Grants("fosite.keys.get"))
	assert.True(t, sc.GetGrantedScopes().Grants("fosite.keys.update"))

	sc.GrantTypes = []string{}
	sc.ResponseTypes = []string{}
	assert.Equal(t, "code", sc.GetResponseTypes()[0])
	assert.Equal(t, "authorization_code", sc.GetGrantTypes()[0])
}

func TestDefaultScope(t *testing.T) {

}
