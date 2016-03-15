package integration_test

import (
	"testing"

	"github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/handler/core/client"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestClientCredentialsFlow(t *testing.T) {
	for _, strategy := range []core.AccessTokenStrategy{
		hmacStrategy,
	} {
		runClientCredentialsFlowTest(t, strategy)
	}
}

func runClientCredentialsFlowTest(t *testing.T, strategy core.AccessTokenStrategy) {
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
			description: "should pass",
			setup: func() {
				f.TokenEndpointHandlers.Append(&client.ClientCredentialsGrantHandler{
					AccessTokenStrategy: strategy,
					Store:               fositeStore,
					AccessTokenLifespan: accessTokenLifespan,
				})
			},
		},
	} {
		c.setup()

		token, err := oauthClient.Token(oauth2.NoContext)
		assert.Equal(t, c.err, err != nil, "(%d) %s\n%s\n%s", k, c.description, c.err, err)
		if !c.err {
			assert.NotEmpty(t, token.AccessToken, "(%d) %s\n%s", k, c.description, token)
		}
		t.Logf("Passed test case %d", k)
	}
}
