package integration_test

import (
	"testing"

	"github.com/ory-am/fosite/compose"
	"github.com/ory-am/fosite/handler/core"
	hst "github.com/ory-am/fosite/handler/core/strategy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestResourceOwnerPasswordCredentialsFlow(t *testing.T) {
	for _, strategy := range []core.AccessTokenStrategy{
		hmacStrategy,
	} {
		runResourceOwnerPasswordCredentialsGrantTest(t, strategy)
	}
}

func runResourceOwnerPasswordCredentialsGrantTest(t *testing.T, strategy core.AccessTokenStrategy) {
	f := compose.Compose(new(compose.Config), fositeStore, strategy, compose.OAuth2ResourceOwnerPasswordCredentialsFactory)
	ts := mockServer(t, f, &mySessionData{
		HMACSession: new(hst.HMACSession),
	})
	defer ts.Close()

	var username, password string
	oauthClient := newOAuth2Client(ts)
	for k, c := range []struct {
		description string
		setup       func()
		err         bool
	}{
		{
			description: "should fail because invalid password",
			setup: func() {
				username = "peter"
				password = "something-wrong"
			},
			err: true,
		},
		{
			description: "should pass",
			setup: func() {
				password = "secret"
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
