package integration_test

import (
	"testing"

	"net/http"
	"time"

	"github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/ory-am/fosite/handler/core/refresh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestRefreshTokenGrant(t *testing.T) {
	for _, strategy := range []core.AccessTokenStrategy{
		hmacStrategy,
	} {
		runRefreshTokenGrantTest(t, strategy)
	}
}

func runRefreshTokenGrantTest(t *testing.T, strategy interface{}) {
	f := newFosite()
	ts := mockServer(t, f, nil)
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	fositeStore.Clients["my-client"].RedirectURIs[0] = ts.URL + "/callback"

	handler := &explicit.AuthorizeExplicitGrantTypeHandler{
		AccessTokenStrategy:       strategy.(core.AccessTokenStrategy),
		RefreshTokenStrategy:      strategy.(core.RefreshTokenStrategy),
		AuthorizeCodeStrategy:     strategy.(core.AuthorizeCodeStrategy),
		AuthorizeCodeGrantStorage: fositeStore,
		AuthCodeLifespan:          time.Minute,
		AccessTokenLifespan:       time.Second,
	}
	f.AuthorizeEndpointHandlers.Append(handler)
	f.TokenEndpointHandlers.Append(handler)
	f.AuthorizedRequestValidators.Append(&core.CoreValidator{
		AccessTokenStrategy: strategy.(core.AccessTokenStrategy),
		AccessTokenStorage:  fositeStore,
	})

	state := "1234567890"
	for k, c := range []struct {
		description string
		setup       func()
		pass        bool
	}{
		{
			description: "should fail because handler not registered",
			setup:       func() {},
			pass:        false,
		},
		{
			description: "should fail because scope missing",
			setup: func() {
				handler := &refresh.RefreshTokenGrantHandler{
					AccessTokenStrategy:      strategy.(core.AccessTokenStrategy),
					RefreshTokenStrategy:     strategy.(core.RefreshTokenStrategy),
					RefreshTokenGrantStorage: fositeStore,
					AccessTokenLifespan:      time.Second,
				}
				f.TokenEndpointHandlers.Append(handler)
			},
			pass: false,
		},
		{
			description: "should pass",
			setup: func() {
				oauthClient.Scopes = []string{"fosite", "offline"}
			},
			pass: true,
		},
	} {
		c.setup()

		resp, err := http.Get(oauthClient.AuthCodeURL(state))
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "(%d) %s", k, c.description)

		if resp.StatusCode == http.StatusOK {
			token, err := oauthClient.Exchange(oauth2.NoContext, resp.Request.URL.Query().Get("code"))
			require.Nil(t, err, "(%d) %s", k, c.description)
			require.NotEmpty(t, token.AccessToken, "(%d) %s", k, c.description)

			token.Expiry = token.Expiry.Add(-time.Hour * 24)
			t.Logf("Token %s", token)

			tokenSource := oauthClient.TokenSource(oauth2.NoContext, token)
			refreshed, err := tokenSource.Token()
			if c.pass {
				require.Nil(t, err, "(%d) %s: %s", k, c.description, err)
				assert.NotEqual(t, token.RefreshToken, refreshed.RefreshToken, "(%d) %s", k, c.description)
				assert.NotEqual(t, token.AccessToken, refreshed.AccessToken, "(%d) %s", k, c.description)
			} else {
				require.NotNil(t, err, "(%d) %s: %s", k, c.description, err)

			}
		}
		t.Logf("Passed test case (%d) %s", k, c.description)
	}
}
