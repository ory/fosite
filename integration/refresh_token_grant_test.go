// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	hoauth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/internal/gen"
	"github.com/ory/fosite/token/jwt"
)

type introspectionResponse struct {
	Active    bool     `json:"active"`
	ClientID  string   `json:"client_id,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Username  string   `json:"username,omitempty"`
}

func TestRefreshTokenFlow(t *testing.T) {
	session := &defaultSession{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Subject: "peter",
			},
			Headers:  &jwt.Headers{},
			Subject:  "peter",
			Username: "peteru",
		},
	}
	fc := new(fosite.Config)
	fc.RefreshTokenLifespan = -1
	fc.GlobalSecret = []byte("some-secret-thats-random-some-secret-thats-random-")
	f := compose.ComposeAllEnabled(fc, fositeStore, gen.MustRSAKey())
	ts := mockServer(t, f, session)
	defer ts.Close()

	oauthClient := newOAuth2Client(ts)
	state := "1234567890"
	fositeStore.Clients["my-client"].(*fosite.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"

	refreshCheckClient := &fosite.DefaultClient{
		ID:            "refresh-client",
		Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
		RedirectURIs:  []string{ts.URL + "/callback"},
		ResponseTypes: []string{"id_token", "code", "token", "token code", "id_token code", "token id_token", "token code id_token"},
		GrantTypes:    []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
		Scopes:        []string{"fosite", "offline", "openid"},
		Audience:      []string{"https://www.ory.sh/api"},
	}
	fositeStore.Clients["refresh-client"] = refreshCheckClient

	fositeStore.Clients["my-client"].(*fosite.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"
	for _, c := range []struct {
		description   string
		setup         func(t *testing.T)
		pass          bool
		params        []oauth2.AuthCodeOption
		check         func(t *testing.T, original, refreshed *oauth2.Token, or, rr *introspectionResponse)
		beforeRefresh func(t *testing.T)
		mockServer    func(t *testing.T) *httptest.Server
	}{
		{
			description: "should fail because refresh scope missing",
			setup: func(t *testing.T) {
				oauthClient.Scopes = []string{"fosite"}
			},
			pass: false,
		},
		{
			description: "should pass but not yield id token",
			setup: func(t *testing.T) {
				oauthClient.Scopes = []string{"offline"}
			},
			pass: true,
			check: func(t *testing.T, original, refreshed *oauth2.Token, or, rr *introspectionResponse) {
				assert.NotEqual(t, original.RefreshToken, refreshed.RefreshToken)
				assert.NotEqual(t, original.AccessToken, refreshed.AccessToken)
				assert.Nil(t, refreshed.Extra("id_token"))
			},
		},
		{
			description: "should pass and yield id token",
			params:      []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("audience", "https://www.ory.sh/api")},
			setup: func(t *testing.T) {
				oauthClient.Scopes = []string{"fosite", "offline", "openid"}
			},
			pass: true,
			check: func(t *testing.T, original, refreshed *oauth2.Token, or, rr *introspectionResponse) {
				assert.NotEqual(t, original.RefreshToken, refreshed.RefreshToken)
				assert.NotEqual(t, original.AccessToken, refreshed.AccessToken)
				assert.NotEqual(t, original.Extra("id_token"), refreshed.Extra("id_token"))
				assert.NotNil(t, refreshed.Extra("id_token"))

				assert.NotEmpty(t, or.Audience)
				assert.NotEmpty(t, or.ClientID)
				assert.NotEmpty(t, or.Scope)
				assert.NotEmpty(t, or.ExpiresAt)
				assert.NotEmpty(t, or.IssuedAt)
				assert.True(t, or.Active)
				assert.EqualValues(t, "peter", or.Subject)
				assert.EqualValues(t, "peteru", or.Username)

				assert.EqualValues(t, or.Audience, rr.Audience)
				assert.EqualValues(t, or.ClientID, rr.ClientID)
				assert.EqualValues(t, or.Scope, rr.Scope)
				assert.NotEqual(t, or.ExpiresAt, rr.ExpiresAt)
				assert.True(t, or.ExpiresAt < rr.ExpiresAt)
				assert.NotEqual(t, or.IssuedAt, rr.IssuedAt)
				assert.True(t, or.IssuedAt < rr.IssuedAt)
				assert.EqualValues(t, or.Active, rr.Active)
				assert.EqualValues(t, or.Subject, rr.Subject)
				assert.EqualValues(t, or.Username, rr.Username)
			},
		},
		{
			description: "should fail because scope is no longer allowed",
			setup: func(t *testing.T) {
				oauthClient.ClientID = refreshCheckClient.ID
				oauthClient.Scopes = []string{"fosite", "offline", "openid"}
			},
			beforeRefresh: func(t *testing.T) {
				refreshCheckClient.Scopes = []string{"offline", "openid"}
			},
			pass: false,
		},
		{
			description: "should fail because audience is no longer allowed",
			params:      []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("audience", "https://www.ory.sh/api")},
			setup: func(t *testing.T) {
				oauthClient.ClientID = refreshCheckClient.ID
				oauthClient.Scopes = []string{"fosite", "offline", "openid"}
				refreshCheckClient.Scopes = []string{"fosite", "offline", "openid"}
			},
			beforeRefresh: func(t *testing.T) {
				refreshCheckClient.Audience = []string{"https://www.not-ory.sh/api"}
			},
			pass: false,
		},
		{
			description: "should fail with expired refresh token",
			setup: func(t *testing.T) {
				fc = new(fosite.Config)
				fc.RefreshTokenLifespan = time.Nanosecond
				fc.GlobalSecret = []byte("some-secret-thats-random-some-secret-thats-random-")
				f = compose.ComposeAllEnabled(fc, fositeStore, gen.MustRSAKey())
				ts = mockServer(t, f, session)

				oauthClient = newOAuth2Client(ts)
				oauthClient.Scopes = []string{"fosite", "offline", "openid"}
				fositeStore.Clients["my-client"].(*fosite.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"
			},
			pass: false,
		},
		{
			description: "should pass with limited but not expired refresh token",
			setup: func(t *testing.T) {
				fc = new(fosite.Config)
				fc.RefreshTokenLifespan = time.Minute
				fc.GlobalSecret = []byte("some-secret-thats-random-some-secret-thats-random-")
				f = compose.ComposeAllEnabled(fc, fositeStore, gen.MustRSAKey())
				ts = mockServer(t, f, session)

				oauthClient = newOAuth2Client(ts)
				oauthClient.Scopes = []string{"fosite", "offline", "openid"}
				fositeStore.Clients["my-client"].(*fosite.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"
			},
			beforeRefresh: func(t *testing.T) {
				refreshCheckClient.Audience = []string{}
			},
			pass:  true,
			check: func(t *testing.T, original, refreshed *oauth2.Token, or, rr *introspectionResponse) {},
		},
		{
			description: "should deny access if original token was reused",
			setup: func(t *testing.T) {
				oauthClient.Scopes = []string{"offline"}
			},
			pass: true,
			check: func(t *testing.T, original, refreshed *oauth2.Token, or, rr *introspectionResponse) {
				tokenSource := oauthClient.TokenSource(context.Background(), original)
				_, err := tokenSource.Token()
				require.Error(t, err)
				require.Equal(t, http.StatusUnauthorized, err.(*oauth2.RetrieveError).Response.StatusCode)

				refreshed.Expiry = refreshed.Expiry.Add(-time.Hour * 24)
				tokenSource = oauthClient.TokenSource(context.Background(), refreshed)
				_, err = tokenSource.Token()
				require.Error(t, err)
				require.Equal(t, http.StatusUnauthorized, err.(*oauth2.RetrieveError).Response.StatusCode)
			},
		},
	} {
		t.Run("case="+c.description, func(t *testing.T) {
			c.setup(t)

			var intro = func(token string, p interface{}) {
				req, err := http.NewRequest("POST", ts.URL+"/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
				require.NoError(t, err)
				req.SetBasicAuth("refresh-client", "foobar")
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r, err := http.DefaultClient.Do(req)
				require.NoError(t, err)
				assert.Equal(t, http.StatusOK, r.StatusCode)

				dec := json.NewDecoder(r.Body)
				dec.DisallowUnknownFields()
				require.NoError(t, dec.Decode(p))
			}

			resp, err := http.Get(oauthClient.AuthCodeURL(state, c.params...))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			if resp.StatusCode != http.StatusOK {
				return
			}

			token, err := oauthClient.Exchange(context.Background(), resp.Request.URL.Query().Get("code"))
			require.NoError(t, err)
			require.NotEmpty(t, token.AccessToken)

			var ob introspectionResponse
			intro(token.AccessToken, &ob)

			token.Expiry = token.Expiry.Add(-time.Hour * 24)

			if c.beforeRefresh != nil {
				c.beforeRefresh(t)
			}

			tokenSource := oauthClient.TokenSource(context.Background(), token)

			// This sleep guarantees time difference in exp/iat
			time.Sleep(time.Second * 2)

			refreshed, err := tokenSource.Token()
			if c.pass {
				require.NoError(t, err)

				var rb introspectionResponse
				intro(refreshed.AccessToken, &rb)
				c.check(t, token, refreshed, &ob, &rb)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestRefreshTokenFlowScopeParameter(t *testing.T) {
	type testCase struct {
		name     string
		scopes   fosite.Arguments
		expected fosite.Arguments
		err      string
	}

	type step struct {
		OAuth2               *oauth2.Token
		SessionAT, SessionRT fosite.Requester
	}

	originalScopes := fosite.Arguments{"openid", "offline", "offline_access", "foo", "bar"}

	scenarios := []struct {
		name      string
		ignore    bool
		checkTime bool
		testCases []testCase
	}{
		{
			"ShouldPassRFC",
			false,
			true,
			[]testCase{
				{
					"ShouldGrantOriginalScopesWhenOmitted",
					nil,
					originalScopes,
					"",
				},
				{
					"ShouldNarrowScopesWhenIncluded",
					fosite.Arguments{"openid", "offline_access", "foo"},
					fosite.Arguments{"openid", "offline_access", "foo"},
					"",
				},
				{
					"ShouldGrantOriginalScopesWhenOmittedAfterNarrowing",
					nil,
					originalScopes,
					"",
				},
				{
					"ShouldGrantOriginalScopesExplicitlyRequested",
					originalScopes,
					originalScopes,
					"",
				},
				{
					"ShouldErrorWhenBroadeningScopesAllowedByClientButNotOriginallyGranted",
					fosite.Arguments{"openid", "offline", "offline_access", "foo", "bar", "baz"},
					nil,
					"The requested scope is invalid, unknown, or malformed. The requested scope 'baz' was not originally granted by the resource owner.",
				},
			},
		},
		{
			"ShouldPassIgnoreFilter",
			true,
			false,
			[]testCase{
				{
					"ShouldGrantOriginalScopesWhenOmitted",
					nil,
					originalScopes,
					"",
				},
				{
					"ShouldNarrowScopesWhenIncluded",
					fosite.Arguments{"openid", "offline_access", "foo"},
					fosite.Arguments{"openid", "offline_access", "foo"},
					"",
				},
				{
					"ShouldGrantOriginalScopesWhenOmittedAfterNarrowing",
					nil,
					originalScopes,
					"",
				},
				{
					"ShouldGrantOriginalScopesExplicitlyRequested",
					originalScopes,
					originalScopes,
					"",
				},
				{
					"ShouldErrorWhenBroadeningScopesAllowedByClientButNotOriginallyGranted",
					fosite.Arguments{"openid", "offline", "offline_access", "foo", "bar", "baz"},
					fosite.Arguments{"openid", "offline", "offline_access", "foo", "bar"},
					"",
				},
			},
		},
	}

	state := "1234567890"

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			ctx := context.Background()

			session := &defaultSession{
				DefaultSession: &openid.DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers:  &jwt.Headers{},
					Subject:  "peter",
					Username: "peteru",
				},
			}

			fc := new(fosite.Config)
			fc.GlobalSecret = []byte("some-secret-thats-random-some-secret-thats-random-")
			fc.ScopeStrategy = fosite.ExactScopeStrategy

			s := compose.NewOAuth2HMACStrategy(fc)

			var f fosite.OAuth2Provider

			if scenario.ignore {
				keyGetter := func(context.Context) (interface{}, error) {
					return gen.MustRSAKey(), nil
				}

				// OAuth2RefreshTokenGrantFactory creates an OAuth2 refresh grant handler and registers
				// an access token, refresh token and authorize code validator.nmj
				factoryRefresh := func(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
					return &hoauth2.RefreshTokenGrantHandler{
						AccessTokenStrategy:                    strategy.(hoauth2.AccessTokenStrategy),
						RefreshTokenStrategy:                   strategy.(hoauth2.RefreshTokenStrategy),
						TokenRevocationStorage:                 storage.(hoauth2.TokenRevocationStorage),
						Config:                                 config,
						IgnoreRequestedScopeNotInOriginalGrant: true,
					}
				}

				f = compose.Compose(
					fc,
					fositeStore,
					&compose.CommonStrategy{
						CoreStrategy:               compose.NewOAuth2HMACStrategy(fc),
						OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, fc),
						Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
					},
					compose.OAuth2AuthorizeExplicitFactory,
					compose.OAuth2AuthorizeImplicitFactory,
					compose.OAuth2ClientCredentialsGrantFactory,
					factoryRefresh,
					compose.OAuth2ResourceOwnerPasswordCredentialsFactory,
					compose.RFC7523AssertionGrantFactory,

					compose.OpenIDConnectExplicitFactory,
					compose.OpenIDConnectImplicitFactory,
					compose.OpenIDConnectHybridFactory,
					compose.OpenIDConnectRefreshFactory,

					compose.OAuth2TokenIntrospectionFactory,
					compose.OAuth2TokenRevocationFactory,

					compose.OAuth2PKCEFactory,
					compose.PushedAuthorizeHandlerFactory,
				)
			} else {
				f = compose.ComposeAllEnabled(fc, fositeStore, gen.MustRSAKey())
			}

			ts := mockServer(t, f, session)
			defer ts.Close()

			client := newOAuth2Client(ts)
			client.Scopes = []string{"openid", "offline", "offline_access", "foo", "bar"}
			client.ClientID = "grant-all-requested-scopes-client"

			testRefreshingClient := &fosite.DefaultClient{
				ID:            "grant-all-requested-scopes-client",
				Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
				RedirectURIs:  []string{ts.URL + "/callback"},
				ResponseTypes: []string{"code"},
				GrantTypes:    []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
				Scopes:        []string{"openid", "offline_access", "offline", "foo", "bar", "baz"},
				Audience:      []string{"https://www.ory.sh/api"},
			}

			fositeStore.Clients["grant-all-requested-scopes-client"] = testRefreshingClient

			entries := make([]step, len(scenario.testCases)+1)

			resp, err := http.Get(client.AuthCodeURL(state))
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			entries[0].OAuth2, err = client.Exchange(ctx, resp.Request.URL.Query().Get("code"), oauth2.SetAuthURLParam("client_id", client.ClientID))

			require.NoError(t, err)
			require.NotEmpty(t, entries[0].OAuth2.AccessToken)
			require.NotEmpty(t, entries[0].OAuth2.RefreshToken)

			assert.Equal(t, strings.Join(originalScopes, " "), entries[0].OAuth2.Extra("scope"))

			entries[0].SessionAT, err = fositeStore.GetAccessTokenSession(ctx, s.AccessTokenSignature(ctx, entries[0].OAuth2.AccessToken), nil)
			require.NoError(t, err)

			entries[0].SessionRT, err = fositeStore.GetRefreshTokenSession(ctx, s.RefreshTokenSignature(ctx, entries[0].OAuth2.RefreshToken), nil)
			require.NoError(t, err)

			assert.ElementsMatch(t, entries[0].SessionAT.GetRequestedScopes(), originalScopes)
			assert.ElementsMatch(t, entries[0].SessionRT.GetRequestedScopes(), originalScopes)
			assert.ElementsMatch(t, entries[0].SessionAT.GetGrantedScopes(), originalScopes)
			assert.ElementsMatch(t, entries[0].SessionRT.GetGrantedScopes(), originalScopes)
			assert.Equal(t, strings.Join(originalScopes, " "), entries[0].OAuth2.Extra("scope"))

			for i, tc := range scenario.testCases {
				t.Run(tc.name, func(t *testing.T) {
					if scenario.checkTime {
						time.Sleep(time.Second)
					}

					idx := i + 1

					opts := []oauth2.AuthCodeOption{
						oauth2.SetAuthURLParam("refresh_token", entries[i].OAuth2.RefreshToken),
						oauth2.SetAuthURLParam("grant_type", "refresh_token"),
					}

					if len(tc.scopes) != 0 {
						opts = append(opts, oauth2.SetAuthURLParam("scope", strings.Join(tc.scopes, " ")), oauth2.SetAuthURLParam("client_id", client.ClientID))
					}

					entries[idx].OAuth2, err = client.Exchange(ctx, "", opts...)
					if len(tc.err) != 0 {
						require.Error(t, err)
						require.Nil(t, entries[idx].OAuth2)
						require.Contains(t, err.Error(), tc.err)

						return
					}

					require.NoError(t, err)
					require.NotEmpty(t, entries[idx].OAuth2.AccessToken)
					require.NotEmpty(t, entries[idx].OAuth2.RefreshToken)

					entries[idx].SessionAT, err = fositeStore.GetAccessTokenSession(ctx, s.AccessTokenSignature(ctx, entries[idx].OAuth2.AccessToken), nil)
					require.NoError(t, err)

					entries[idx].SessionRT, err = fositeStore.GetRefreshTokenSession(ctx, s.RefreshTokenSignature(ctx, entries[idx].OAuth2.RefreshToken), nil)
					require.NoError(t, err)

					if len(tc.scopes) != 0 {
						assert.ElementsMatch(t, entries[idx].SessionAT.GetRequestedScopes(), tc.scopes)
						assert.Equal(t, strings.Join(tc.expected, " "), entries[idx].OAuth2.Extra("scope"))
					} else {
						assert.ElementsMatch(t, entries[idx].SessionAT.GetRequestedScopes(), originalScopes)
						assert.Equal(t, strings.Join(originalScopes, " "), entries[idx].OAuth2.Extra("scope"))
					}
					assert.ElementsMatch(t, entries[idx].SessionAT.GetGrantedScopes(), tc.expected)
					assert.ElementsMatch(t, entries[idx].SessionRT.GetRequestedScopes(), originalScopes)
					assert.ElementsMatch(t, entries[idx].SessionRT.GetGrantedScopes(), originalScopes)

					var (
						j     int
						entry step
					)

					assert.Equal(t, entries[idx].SessionAT.GetID(), entries[idx].SessionRT.GetID())

					for j, entry = range entries {
						if j == idx {
							break
						}

						assert.Equal(t, entries[idx].SessionAT.GetID(), entry.SessionAT.GetID())
						assert.Equal(t, entries[idx].SessionAT.GetID(), entry.SessionRT.GetID())
						assert.Equal(t, entries[idx].SessionRT.GetID(), entry.SessionAT.GetID())
						assert.Equal(t, entries[idx].SessionRT.GetID(), entry.SessionRT.GetID())

						if scenario.checkTime {
							assert.Greater(t, entries[idx].SessionAT.GetSession().GetExpiresAt(fosite.AccessToken).Unix(), entry.SessionAT.GetSession().GetExpiresAt(fosite.AccessToken).Unix())
							assert.Greater(t, entries[idx].SessionRT.GetSession().GetExpiresAt(fosite.RefreshToken).Unix(), entry.SessionRT.GetSession().GetExpiresAt(fosite.RefreshToken).Unix())
							assert.Greater(t, entries[idx].SessionAT.GetRequestedAt().Unix(), entry.SessionAT.GetRequestedAt().Unix())
							assert.Greater(t, entries[idx].SessionRT.GetRequestedAt().Unix(), entry.SessionRT.GetRequestedAt().Unix())
						}
					}
				})
			}
		})
	}
}
