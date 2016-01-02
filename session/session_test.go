package session

import (
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/generator"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewAuthorizeSession(t *testing.T) {
	ar := &fosite.AuthorizeRequest{
		ResponseTypes: []string{"code token"},
		Client:        &client.SecureClient{ID: "client"},
		Scopes:        []string{"email id_token"},
		RedirectURI:   "https://foo.bar/cb",
		State:         "randomState",
		ExpiresIn:     30,
		Code:          &generator.Token{Key: "key", Signature: "sig"},
	}
	as := NewAuthorizeSession(ar, "1234")

	assert.Equal(t, ar.Client.GetID(), as.GetClientID())
	assert.Equal(t, ar.Code.Signature, as.GetCodeSignature())
	assert.Equal(t, ar.RedirectURI, as.GetRedirectURI())
	assert.Equal(t, ar.ResponseTypes, as.GetResponseTypes())
	assert.Equal(t, ar.Scopes, as.GetScopes())
	assert.Equal(t, "1234", as.GetUserID())
}
