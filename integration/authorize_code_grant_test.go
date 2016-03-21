package integration_test

import (
	"testing"

	"net/http"
	"time"

	"github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestAuthorizeCodeGrant(t *testing.T) {
	for _, strategy := range []core.AccessTokenStrategy{
		hmacStrategy,
	} {
		runAuthorizeCodeGrantTest(t, strategy)
	}
}

func runAuthorizeCodeGrantTest(t *testing.T, strategy interface{}) {
	f := newFosite()
	ts := mockServer(t, f, nil)
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	fositeStore.Clients["my-client"].RedirectURIs[0] = ts.URL + "/callback"

	var state string
	for k, c := range []struct {
		description    string
		setup          func()
		authStatusCode int
	}{
		{
			description: "should fail because handler not registered",
			setup: func() {
				oauthClient.ClientID = "1234"
			},
			authStatusCode: http.StatusBadRequest,
		},
		{
			description: "should fail (and redirect) because handler not registered",
			setup: func() {
				oauthClient = newOAuth2Client(ts)
			},
			authStatusCode: http.StatusNotAcceptable,
		},
		{
			description: "should pass",
			setup: func() {
				state = "12345678901234567890"
				handler := &explicit.AuthorizeExplicitGrantTypeHandler{
					AccessTokenStrategy:       strategy.(core.AccessTokenStrategy),
					RefreshTokenStrategy:      strategy.(core.RefreshTokenStrategy),
					AuthorizeCodeStrategy:     strategy.(core.AuthorizeCodeStrategy),
					AuthorizeCodeGrantStorage: fositeStore,
					AuthCodeLifespan:          time.Minute,
					AccessTokenLifespan:       time.Hour,
				}
				f.AuthorizeEndpointHandlers.Append(handler)
				f.TokenEndpointHandlers.Append(handler)
				f.AuthorizedRequestValidators.Append(&core.CoreValidator{
					AccessTokenStrategy: strategy.(core.AccessTokenStrategy),
					AccessTokenStorage:  fositeStore,
				})
			},
			authStatusCode: http.StatusOK,
		},
	} {
		c.setup()

		resp, err := http.Get(oauthClient.AuthCodeURL(state))
		require.Nil(t, err)
		require.Equal(t, c.authStatusCode, resp.StatusCode, "(%d) %s", k, c.description)

		if resp.StatusCode == http.StatusOK {

			token, err := oauthClient.Exchange(oauth2.NoContext, resp.Request.URL.Query().Get("code"))
			require.Nil(t, err, "(%d) %s", k, c.description)
			require.NotEmpty(t, token.AccessToken, "(%d) %s", k, c.description)

			httpClient := oauthClient.Client(oauth2.NoContext, token)
			resp, err := httpClient.Get(ts.URL + "/info")
			require.Nil(t, err, "(%d) %s", k, c.description)
			assert.Equal(t, http.StatusNoContent, resp.StatusCode, "(%d) %s", k, c.description)
		}
		t.Logf("Passed test case (%d) %s", k, c.description)
	}
}
