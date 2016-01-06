package fosite_test

import (
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/generator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
)

func TestNewAuthorizeSessionSQL(t *testing.T) {
	type extra struct {
		Foo string
		Bar string
	}

	var extraOut extra
	var extraIn = &extra{
		Foo: "foo",
		Bar: "bar",
	}
	redir, _ := url.Parse("http://foo.bar/cb")

	ar := &AuthorizeRequest{
		ResponseTypes: []string{"code token"},
		Client:        &client.SecureClient{ID: "client"},
		Scopes:        []string{"email id_token"},
		RedirectURI:   redir,
		State:         "randomState",
		ExpiresIn:     30,
		Code:          &generator.Token{Key: "key", Signature: "sig"},
	}

	as := NewAuthorizeSessionSQL(ar, "1234")
	err := as.SetExtra(extraIn)
	require.Nil(t, err, "%s", err)
	err = as.WriteExtra(&extraOut)
	require.Nil(t, err, "%s", err)
	assert.Equal(t, extraIn, &extraOut)

	assert.Equal(t, ar.Client.GetID(), as.GetClientID())
	assert.Equal(t, ar.Code.Signature, as.GetCodeSignature())
	assert.Equal(t, ar.RedirectURI.String(), as.GetRedirectURI())
	assert.Equal(t, ar.ResponseTypes, as.GetResponseTypes())
	assert.Equal(t, ar.Scopes, as.GetScopes())
	assert.Equal(t, "1234", as.GetUserID())
}
