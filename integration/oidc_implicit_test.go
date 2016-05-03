package integration_test

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-errors/errors"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/ory-am/fosite/handler/core/implicit"
	"github.com/ory-am/fosite/handler/oidc"
	"github.com/ory-am/fosite/handler/oidc/hybrid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/ory-am/fosite/handler/core"
	idimplicit "github.com/ory-am/fosite/handler/oidc/implicit"
	"github.com/ory-am/fosite/handler/oidc/strategy"
	"github.com/ory-am/fosite/token/jwt"
)

func TestOIDCImplicitGrants(t *testing.T) {
	session := &strategy.DefaultSession{
		Claims:  &jwt.IDTokenClaims{
			Subject: "peter",
		},
		Headers: &jwt.Headers{},
	}
	f := newFosite()
	ts := mockServer(t, f, session)
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	fositeStore.Clients["my-client"].RedirectURIs[0] = ts.URL + "/callback"

	explicitHandler := &explicit.AuthorizeExplicitGrantTypeHandler{
		AccessTokenStrategy:       hmacStrategy,
		RefreshTokenStrategy:      hmacStrategy,
		AuthorizeCodeStrategy:     hmacStrategy,
		AuthorizeCodeGrantStorage: fositeStore,
		AuthCodeLifespan:          time.Minute,
		AccessTokenLifespan:       time.Hour,
	}
	f.AuthorizeEndpointHandlers.Append(explicitHandler)
	f.TokenEndpointHandlers.Append(explicitHandler)

	implicitHandler := &implicit.AuthorizeImplicitGrantTypeHandler{
		AccessTokenStrategy: hmacStrategy,
		AccessTokenStorage:  fositeStore,
		AccessTokenLifespan: time.Hour,
	}
	f.AuthorizeEndpointHandlers.Append(implicitHandler)

	f.AuthorizeEndpointHandlers.Append(&idimplicit.OpenIDConnectImplicitHandler{
		AuthorizeImplicitGrantTypeHandler: implicitHandler,
		IDTokenHandleHelper: &oidc.IDTokenHandleHelper{
			IDTokenStrategy: idTokenStrategy,
		},
	})
	f.AuthorizeEndpointHandlers.Append(&hybrid.OpenIDConnectHybridHandler{
		AuthorizeImplicitGrantTypeHandler: implicitHandler,
		AuthorizeExplicitGrantTypeHandler: explicitHandler,
		IDTokenHandleHelper: &oidc.IDTokenHandleHelper{
			IDTokenStrategy: idTokenStrategy,
		},
	})
	f.AuthorizedRequestValidators.Append(&core.CoreValidator{
		AccessTokenStrategy: hmacStrategy,
		AccessTokenStorage:  fositeStore,
	})

	var state = "12345678901234567890"
	for k, c := range []struct {
		responseType string
		description  string
		nonce        string
		setup        func()
		hasToken     bool
		hasCode      bool
	}{
		{
			description:  "should pass without id token",
			responseType: "token",
			setup: func() {
				oauthClient.Scopes = []string{f.MandatoryScope}
			},
		},
		{

			responseType: "id_token%20token",
			nonce:        "1111111111111111",
			description:  "should pass id token (id_token token)",
			setup: func() {
				oauthClient.Scopes = []string{f.MandatoryScope, "openid"}
			},
			hasToken: true,
		},
		{

			responseType: "token%20id_token%20code",
			nonce:        "1111111111111111",
			description:  "should pass id token (id_token token)",
			setup: func() {},
			hasToken: true,
			hasCode:  true,
		},
	} {
		c.setup()

		var callbackURL *url.URL
		authURL := strings.Replace(oauthClient.AuthCodeURL(state), "response_type=code", "response_type="+c.responseType, -1) + "&nonce=" + c.nonce
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				callbackURL = req.URL
				return errors.New("Dont follow redirects")
			},
		}
		resp, err := client.Get(authURL)
		require.NotNil(t, err, "(%d) %s", k, c.description)

		t.Logf("Response: %s", callbackURL.String())
		fragment, err := url.ParseQuery(callbackURL.Fragment)
		require.Nil(t, err, "(%d) %s", k, c.description)

		expires, err := strconv.Atoi(fragment.Get("expires_in"))
		require.Nil(t, err, "(%d) %s", k, c.description)

		token := &oauth2.Token{
			AccessToken:  fragment.Get("access_token"),
			TokenType:    fragment.Get("token_type"),
			RefreshToken: fragment.Get("refresh_token"),
			Expiry:       time.Now().Add(time.Duration(expires) * time.Second),
		}

		if c.hasToken {
			assert.NotEmpty(t, fragment.Get("id_token"), "(%d) %s", k, c.description)
		} else {
			assert.Empty(t, fragment.Get("id_token"), "(%d) %s", k, c.description)
		}

		if c.hasCode {
			assert.NotEmpty(t, fragment.Get("code"), "(%d) %s", k, c.description)
		} else {
			assert.Empty(t, fragment.Get("code"), "(%d) %s", k, c.description)
		}

		httpClient := oauthClient.Client(oauth2.NoContext, token)
		resp, err = httpClient.Get(ts.URL + "/info")
		require.Nil(t, err, "(%d) %s", k, c.description)
		assert.Equal(t, http.StatusNoContent, resp.StatusCode, "(%d) %s", k, c.description)
		t.Logf("Passed test case (%d) %s", k, c.description)
	}
}
