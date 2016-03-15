package integration_test

import (
	"testing"

	"github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/handler/core/client"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"github.com/stretchr/testify/require"
)

func TestResourceOwnerPasswordCredentialsGrant(t *testing.T) {
	for _, strategy := range []core.AccessTokenStrategy{
		hmacStrategy,
	} {
		runResourceOwnerPasswordCredentialsGrantTest(t, strategy)
	}
}

func runResourceOwnerPasswordCredentialsGrantTest(t *testing.T, strategy core.AccessTokenStrategy) {
	f := newFosite()
	ts := mockServer(t, f, nil)
	defer ts.Close()

	oauthClient := newOAuth2AppClient(ts)
	for k, c := range []struct {
		description string
		setup       func()
		err         bool
	}{
		{
			description: "should fail because handler not registered",
			setup:       func() {},
			err:         true,
		},
		{
			description: "should fail because unknown client",
			setup: func() {
				f.TokenEndpointHandlers.Append(&client.ClientCredentialsGrantHandler{
					AccessTokenStrategy: strategy,
					Store:               fositeStore,
					AccessTokenLifespan: accessTokenLifespan,
				})

				oauthClient = &clientcredentials.Config{
					ClientID:     "my-client-wrong",
					ClientSecret: "foobar",
					Scopes:       []string{"fosite"},
					TokenURL:     ts.URL + "/token",
				}
			},
			err:         true,
		},
		{
			description: "should fail because unknown client",
			setup: func() {
				oauthClient = &clientcredentials.Config{
					ClientID:     "my-client",
					ClientSecret: "foobar-wrong",
					Scopes:       []string{"fosite"},
					TokenURL:     ts.URL + "/token",
				}
			},
			err:         true,
		},
		{
			description: "should fail because unknown client",
			setup: func() {
				oauthClient = &clientcredentials.Config{
					ClientID:     "my-client",
					ClientSecret: "foobar",
					Scopes:       []string{""},
					TokenURL:     ts.URL + "/token",
				}
			},
			err:         true,
		},
		{
			description: "should pass",
			setup: func() {
				oauthClient = newOAuth2AppClient(ts)
			},
		},
	} {
		c.setup()

		token, err := oauthClient.Token(oauth2.NoContext)
		require.Equal(t, c.err, err != nil, "(%d) %s\n%s\n%s", k, c.description, c.err, err)
		if !c.err {
			assert.NotEmpty(t, token.AccessToken, "(%d) %s\n%s", k, c.description, token)
		}
		t.Logf("Passed test case %d", k)
	}
}
