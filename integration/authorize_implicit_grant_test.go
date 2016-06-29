package integration_test

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/handler/core/implicit"
	hst "github.com/ory-am/fosite/handler/core/strategy"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestAuthorizeImplicitGrant(t *testing.T) {
	for _, strategy := range []core.AccessTokenStrategy{
		hmacStrategy,
	} {
		runTestAuthorizeImplicitGrant(t, strategy)
	}
}

func runTestAuthorizeImplicitGrant(t *testing.T, strategy interface{}) {
	f := newFosite()
	ts := mockServer(t, f, &mySessionData{
		HMACSession: new(hst.HMACSession),
	})
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
			description: "should pass",
			setup: func() {
				state = "12345678901234567890"
				handler := &implicit.AuthorizeImplicitGrantTypeHandler{
					AccessTokenStrategy: strategy.(core.AccessTokenStrategy),
					AccessTokenStorage:  fositeStore,
					AccessTokenLifespan: time.Hour,
				}
				f.AuthorizeEndpointHandlers.Append(handler)
				f.AuthorizedRequestValidators.Append(&core.CoreValidator{
					AccessTokenStrategy: strategy.(core.AccessTokenStrategy),
					AccessTokenStorage:  fositeStore,
				})
			},
			authStatusCode: http.StatusOK,
		},
	} {
		c.setup()

		var callbackURL *url.URL
		authURL := strings.Replace(oauthClient.AuthCodeURL(state), "response_type=code", "response_type=token", -1)
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				callbackURL = req.URL
				return errors.New("Dont follow redirects")
			},
		}
		resp, err := client.Get(authURL)
		require.NotNil(t, err)

		if resp.StatusCode == http.StatusOK {
			fragment, err := url.ParseQuery(callbackURL.Fragment)
			require.Nil(t, err)
			expires, err := strconv.Atoi(fragment.Get("expires_in"))
			require.Nil(t, err)
			token := &oauth2.Token{
				AccessToken:  fragment.Get("access_token"),
				TokenType:    fragment.Get("token_type"),
				RefreshToken: fragment.Get("refresh_token"),
				Expiry:       time.Now().Add(time.Duration(expires) * time.Second),
			}

			httpClient := oauthClient.Client(oauth2.NoContext, token)
			resp, err := httpClient.Get(ts.URL + "/info")
			require.Nil(t, err, "(%d) %s", k, c.description)
			assert.Equal(t, http.StatusNoContent, resp.StatusCode, "(%d) %s", k, c.description)
		}
		t.Logf("Passed test case (%d) %s", k, c.description)
	}
}
