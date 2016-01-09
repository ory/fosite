package fosite

import (
	"github.com/ory-am/fosite/client"
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"
	"time"
)

func TestAuthorizeRequest(t *testing.T) {
	var urlparse = func(rawurl string) *url.URL {
		u, _ := url.Parse(rawurl)
		return u
	}

	for k, c := range []struct {
		ar           *AuthorizeRequest
		isRedirValid bool
	}{
		{
			ar:           &AuthorizeRequest{},
			isRedirValid: false,
		},
		{
			ar: &AuthorizeRequest{
				RedirectURI: urlparse("http://foobar"),
			},
			isRedirValid: false,
		},
		{
			ar: &AuthorizeRequest{
				Client:      &client.SecureClient{RedirectURIs: []string{""}},
				RedirectURI: urlparse("http://foobar"),
			},
			isRedirValid: false,
		},
		{
			ar: &AuthorizeRequest{
				Client:      &client.SecureClient{RedirectURIs: []string{""}},
				RedirectURI: urlparse(""),
			},
			isRedirValid: false,
		},
		{
			ar: &AuthorizeRequest{
				Client:      &client.SecureClient{RedirectURIs: []string{}},
				RedirectURI: urlparse(""),
			},
			isRedirValid: false,
		},
		{
			ar: &AuthorizeRequest{
				Client:      &client.SecureClient{RedirectURIs: []string{"http://foobar.com#123"}},
				RedirectURI: urlparse("http://foobar.com#123"),
			},
			isRedirValid: false,
		},
		{
			ar: &AuthorizeRequest{
				Client:      &client.SecureClient{RedirectURIs: []string{"http://foobar.com"}},
				RedirectURI: urlparse("http://foobar.com#123"),
			},
			isRedirValid: false,
		},
		{
			ar: &AuthorizeRequest{
				Client:        &client.SecureClient{RedirectURIs: []string{"http://foobar.com/cb"}},
				RedirectURI:   urlparse("http://foobar.com/cb"),
				RequestedAt:   time.Now(),
				ResponseTypes: []string{"foo", "bar"},
				Scopes:        []string{"foo", "bar"},
				State:         "foobar",
			},
			isRedirValid: true,
		},
	} {
		assert.Equal(t, c.ar.Client, c.ar.GetClient(), "%d", k)
		assert.Equal(t, c.ar.RedirectURI, c.ar.GetRedirectURI(), "%d", k)
		assert.Equal(t, c.ar.RequestedAt, c.ar.GetRequestedAt(), "%d", k)
		assert.Equal(t, c.ar.ResponseTypes, c.ar.GetResponseTypes(), "%d", k)
		assert.Equal(t, c.ar.Scopes, c.ar.GetScopes(), "%d", k)
		assert.Equal(t, c.ar.State, c.ar.GetState(), "%d", k)
		assert.Equal(t, c.isRedirValid, c.ar.IsRedirectURIValid(), "%d", k)
	}
}
