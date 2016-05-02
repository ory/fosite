package integration_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/ory-am/fosite/handler/oidc"
	oidcexp "github.com/ory-am/fosite/handler/oidc/explicit"
	"github.com/ory-am/fosite/handler/oidc/strategy"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestOpenIDConnectExplicit(t *testing.T) {
	session := &strategy.IDTokenSession{
		Claims:  &jwt.IDTokenClaims{
			Subject: "peter",
		},
		Headers: &jwt.Header{},
	}
	f := newFosite()
	ts := mockServer(t, f, session)

	defer ts.Close()

	strategy := hmacStrategy
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
				oauthClient.Scopes = []string{"fosite", "openid"}
				handler := &explicit.AuthorizeExplicitGrantTypeHandler{
					AccessTokenStrategy:       strategy,
					RefreshTokenStrategy:      strategy,
					AuthorizeCodeStrategy:     strategy,
					AuthorizeCodeGrantStorage: fositeStore,
					AuthCodeLifespan:          time.Minute,
					AccessTokenLifespan:       time.Hour,
				}
				f.AuthorizeEndpointHandlers.Append(handler)
				f.TokenEndpointHandlers.Append(handler)

				idcHandler := &oidcexp.OpenIDConnectExplicitHandler{
					OpenIDConnectRequestStorage: fositeStore,
					IDTokenHandleHelper: &oidc.IDTokenHandleHelper{
						IDTokenStrategy: idTokenStrategy,
					},
				}
				f.AuthorizeEndpointHandlers.Append(idcHandler)
				f.TokenEndpointHandlers.Append(idcHandler)
				f.AuthorizedRequestValidators.Append(&core.CoreValidator{
					AccessTokenStrategy: hmacStrategy,
					AccessTokenStorage:  fositeStore,
				})
			},
			authStatusCode: http.StatusOK,
		},
	} {
		c.setup()

		resp, err := http.Get(oauthClient.AuthCodeURL(state) + "&nonce=1234567890")
		require.Nil(t, err)
		require.Equal(t, c.authStatusCode, resp.StatusCode, "(%d) %s", k, c.description)

		if resp.StatusCode == http.StatusOK {
			token, err := oauthClient.Exchange(oauth2.NoContext, resp.Request.URL.Query().Get("code"))
			require.Nil(t, err, "(%d) %s", k, c.description)
			require.NotEmpty(t, token.AccessToken, "(%d) %s", k, c.description)
			require.NotEmpty(t, token.Extra("id_token"), "(%d) %s", k, c.description)
		}
		t.Logf("Passed test case (%d) %s", k, c.description)
	}
}
