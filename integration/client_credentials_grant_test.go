package integration_test

import (
	"testing"

	"github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/handler/core/owner"
	hst "github.com/ory-am/fosite/handler/core/strategy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestClientCredentialsGrabt(t *testing.T) {
	for _, strategy := range []core.AccessTokenStrategy{
		hmacStrategy,
	} {
		runClientCredentialsGrantTest(t, strategy)
	}
}

func runClientCredentialsGrantTest(t *testing.T, strategy core.AccessTokenStrategy) {
	f := newFosite()
	ts := mockServer(t, f, &mySessionData{
		HMACSession: new(hst.HMACSession),
	})
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	var username string
	var password string
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
				f.TokenEndpointHandlers.Append(&owner.ResourceOwnerPasswordCredentialsGrantHandler{
					HandleHelper: &core.HandleHelper{
						AccessTokenStrategy: strategy,
						AccessTokenStorage:  fositeStore,
						AccessTokenLifespan: accessTokenLifespan,
					},
					ResourceOwnerPasswordCredentialsGrantStorage: fositeStore,
				})
				f.Validators.Append(&core.CoreValidator{
					AccessTokenStrategy: strategy.(core.AccessTokenStrategy),
					AccessTokenStorage:  fositeStore,
				})
			},
			err: true,
		},
		{
			description: "should fail because user does not exist",
			setup: func() {
				username = "not-existent"
				password = "wrong"
			},
			err: true,
		},
		{
			description: "should fail because wrong credentials",
			setup: func() {
				username = "peter"
				password = "wrong"
			},
			err: true,
		},
		{
			description: "should pass",
			setup: func() {
				username = "peter"
				password = "foobar"
			},
		},
	} {
		c.setup()

		token, err := oauthClient.PasswordCredentialsToken(oauth2.NoContext, username, password)
		require.Equal(t, c.err, err != nil, "(%d) %s\n%s\n%s", k, c.description, c.err, err)
		if !c.err {
			assert.NotEmpty(t, token.AccessToken, "(%d) %s\n%s", k, c.description, token)
		}
		t.Logf("Passed test case %d", k)
	}
}
