// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/ory/fosite/internal"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

func TestRefreshFlow_HandleTokenEndpointRequest(t *testing.T) {
	var areq *fosite.AccessRequest
	sess := &fosite.DefaultSession{Subject: "othersub"}
	expiredSess := &fosite.DefaultSession{
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.RefreshToken: time.Now().UTC().Add(-time.Hour),
		},
	}

	for k, strategy := range map[string]RefreshTokenStrategy{
		"hmac": &hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()
			var handler *RefreshTokenGrantHandler
			for _, c := range []struct {
				description string
				setup       func(config *fosite.Config)
				expectErr   error
				expect      func(t *testing.T)
			}{
				{
					description: "should fail because not responsible",
					expectErr:   fosite.ErrUnknownRequest,
					setup: func(config *fosite.Config) {
						areq.GrantTypes = fosite.Arguments{"123"}
					},
				},
				{
					description: "should fail because token invalid",
					setup: func(config *fosite.Config) {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"refresh_token"}}

						areq.Form.Add("refresh_token", "some.refreshtokensig")
					},
					expectErr: fosite.ErrInvalidGrant,
				},
				{
					description: "should fail because token is valid but does not exist",
					setup: func(config *fosite.Config) {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"refresh_token"}}

						token, _, err := strategy.GenerateRefreshToken(context.Background(), nil)
						require.NoError(t, err)
						areq.Form.Add("refresh_token", token)
					},
					expectErr: fosite.ErrInvalidGrant,
				},
				{
					description: "should fail because client mismatches",
					setup: func(config *fosite.Config) {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{
							ID:         "foo",
							GrantTypes: fosite.Arguments{"refresh_token"},
						}

						token, sig, err := strategy.GenerateRefreshToken(context.Background(), nil)
						require.NoError(t, err)

						areq.Form.Add("refresh_token", token)
						err = store.CreateRefreshTokenSession(context.Background(), sig, &fosite.Request{
							Client:       &fosite.DefaultClient{ID: ""},
							GrantedScope: []string{"offline"},
							Session:      sess,
						})
						require.NoError(t, err)
					},
					expectErr: fosite.ErrInvalidGrant,
				},
				{
					description: "should fail because token is expired",
					setup: func(config *fosite.Config) {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{
							ID:         "foo",
							GrantTypes: fosite.Arguments{"refresh_token"},
							Scopes:     []string{"foo", "bar", "offline"},
						}

						token, sig, err := strategy.GenerateRefreshToken(context.Background(), nil)
						require.NoError(t, err)

						areq.Form.Add("refresh_token", token)
						err = store.CreateRefreshTokenSession(context.Background(), sig, &fosite.Request{
							Client:         areq.Client,
							GrantedScope:   fosite.Arguments{"foo", "offline"},
							RequestedScope: fosite.Arguments{"foo", "bar", "offline"},
							Session:        expiredSess,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Round(time.Hour),
						})
						require.NoError(t, err)
					},
					expectErr: fosite.ErrInvalidGrant,
				},
				{
					description: "should fail because offline scope has been granted but client no longer allowed to request it",
					setup: func(config *fosite.Config) {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{
							ID:         "foo",
							GrantTypes: fosite.Arguments{"refresh_token"},
						}

						token, sig, err := strategy.GenerateRefreshToken(context.Background(), nil)
						require.NoError(t, err)

						areq.Form.Add("refresh_token", token)
						err = store.CreateRefreshTokenSession(context.Background(), sig, &fosite.Request{
							Client:         areq.Client,
							GrantedScope:   fosite.Arguments{"foo", "offline"},
							RequestedScope: fosite.Arguments{"foo", "offline"},
							Session:        sess,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Round(time.Hour),
						})
						require.NoError(t, err)
					},
					expectErr: fosite.ErrInvalidScope,
				},
				{
					description: "should pass",
					setup: func(config *fosite.Config) {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{
							ID:         "foo",
							GrantTypes: fosite.Arguments{"refresh_token"},
							Scopes:     []string{"foo", "bar", "offline"},
						}

						token, sig, err := strategy.GenerateRefreshToken(context.Background(), nil)
						require.NoError(t, err)

						areq.Form.Add("refresh_token", token)

						orReqID := areq.GetID() + "_OR"
						areq.Form.Add("or_request_id", orReqID)
						err = store.CreateRefreshTokenSession(context.Background(), sig, &fosite.Request{
							ID:             orReqID,
							Client:         areq.Client,
							GrantedScope:   fosite.Arguments{"foo", "offline"},
							RequestedScope: fosite.Arguments{"foo", "bar", "offline"},
							Session:        sess,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Round(time.Hour),
						})
						require.NoError(t, err)
					},
					expect: func(t *testing.T) {
						assert.NotEqual(t, sess, areq.Session)
						assert.NotEqual(t, time.Now().UTC().Add(-time.Hour).Round(time.Hour), areq.RequestedAt)
						assert.Equal(t, fosite.Arguments{"foo", "offline"}, areq.GrantedScope)
						assert.Equal(t, fosite.Arguments{"foo", "bar", "offline"}, areq.RequestedScope)
						assert.NotEqual(t, url.Values{"foo": []string{"bar"}}, areq.Form)
						assert.Equal(t, time.Now().Add(time.Hour).UTC().Round(time.Second), areq.GetSession().GetExpiresAt(fosite.AccessToken))
						assert.Equal(t, time.Now().Add(time.Hour).UTC().Round(time.Second), areq.GetSession().GetExpiresAt(fosite.RefreshToken))
						assert.EqualValues(t, areq.Form.Get("or_request_id"), areq.GetID(), "Requester ID should be replaced based on the refresh token session")
					},
				},
				{
					description: "should pass with custom client lifespans",
					setup: func(config *fosite.Config) {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClientWithCustomTokenLifespans{
							DefaultClient: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: fosite.Arguments{"refresh_token"},
								Scopes:     []string{"foo", "bar", "offline"},
							},
						}

						areq.Client.(*fosite.DefaultClientWithCustomTokenLifespans).SetTokenLifespans(&internal.TestLifespans)

						token, sig, err := strategy.GenerateRefreshToken(context.Background(), nil)
						require.NoError(t, err)

						areq.Form.Add("refresh_token", token)
						err = store.CreateRefreshTokenSession(context.Background(), sig, &fosite.Request{
							Client:         areq.Client,
							GrantedScope:   fosite.Arguments{"foo", "offline"},
							RequestedScope: fosite.Arguments{"foo", "bar", "offline"},
							Session:        sess,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Round(time.Hour),
						})
						require.NoError(t, err)
					},
					expect: func(t *testing.T) {
						assert.NotEqual(t, sess, areq.Session)
						assert.NotEqual(t, time.Now().UTC().Add(-time.Hour).Round(time.Hour), areq.RequestedAt)
						assert.Equal(t, fosite.Arguments{"foo", "offline"}, areq.GrantedScope)
						assert.Equal(t, fosite.Arguments{"foo", "bar", "offline"}, areq.RequestedScope)
						assert.NotEqual(t, url.Values{"foo": []string{"bar"}}, areq.Form)
						internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.RefreshTokenGrantAccessTokenLifespan).UTC(), areq.GetSession().GetExpiresAt(fosite.AccessToken), time.Minute)
						internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.RefreshTokenGrantRefreshTokenLifespan).UTC(), areq.GetSession().GetExpiresAt(fosite.RefreshToken), time.Minute)
					},
				},
				{
					description: "should fail without offline scope",
					setup: func(config *fosite.Config) {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{
							ID:         "foo",
							GrantTypes: fosite.Arguments{"refresh_token"},
							Scopes:     []string{"foo", "bar"},
						}

						token, sig, err := strategy.GenerateRefreshToken(context.Background(), nil)
						require.NoError(t, err)

						areq.Form.Add("refresh_token", token)
						err = store.CreateRefreshTokenSession(context.Background(), sig, &fosite.Request{
							Client:         areq.Client,
							GrantedScope:   fosite.Arguments{"foo"},
							RequestedScope: fosite.Arguments{"foo", "bar"},
							Session:        sess,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Round(time.Hour),
						})
						require.NoError(t, err)
					},
					expectErr: fosite.ErrScopeNotGranted,
				},
				{
					description: "should pass without offline scope when configured to allow refresh tokens",
					setup: func(config *fosite.Config) {
						config.RefreshTokenScopes = []string{}
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{
							ID:         "foo",
							GrantTypes: fosite.Arguments{"refresh_token"},
							Scopes:     []string{"foo", "bar"},
						}

						token, sig, err := strategy.GenerateRefreshToken(context.Background(), nil)
						require.NoError(t, err)

						areq.Form.Add("refresh_token", token)
						err = store.CreateRefreshTokenSession(context.Background(), sig, &fosite.Request{
							Client:         areq.Client,
							GrantedScope:   fosite.Arguments{"foo"},
							RequestedScope: fosite.Arguments{"foo", "bar"},
							Session:        sess,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Round(time.Hour),
						})
						require.NoError(t, err)
					},
					expect: func(t *testing.T) {
						assert.NotEqual(t, sess, areq.Session)
						assert.NotEqual(t, time.Now().UTC().Add(-time.Hour).Round(time.Hour), areq.RequestedAt)
						assert.Equal(t, fosite.Arguments{"foo"}, areq.GrantedScope)
						assert.Equal(t, fosite.Arguments{"foo", "bar"}, areq.RequestedScope)
						assert.NotEqual(t, url.Values{"foo": []string{"bar"}}, areq.Form)
						assert.Equal(t, time.Now().Add(time.Hour).UTC().Round(time.Second), areq.GetSession().GetExpiresAt(fosite.AccessToken))
						assert.Equal(t, time.Now().Add(time.Hour).UTC().Round(time.Second), areq.GetSession().GetExpiresAt(fosite.RefreshToken))
					},
				},
				{
					description: "should deny access on token reuse",
					setup: func(config *fosite.Config) {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{
							ID:         "foo",
							GrantTypes: fosite.Arguments{"refresh_token"},
							Scopes:     []string{"foo", "bar", "offline"},
						}

						token, sig, err := strategy.GenerateRefreshToken(context.Background(), nil)
						require.NoError(t, err)

						areq.Form.Add("refresh_token", token)
						req := &fosite.Request{
							Client:         areq.Client,
							GrantedScope:   fosite.Arguments{"foo", "offline"},
							RequestedScope: fosite.Arguments{"foo", "bar", "offline"},
							Session:        sess,
							Form:           url.Values{"foo": []string{"bar"}},
							RequestedAt:    time.Now().UTC().Add(-time.Hour).Round(time.Hour),
						}
						err = store.CreateRefreshTokenSession(context.Background(), sig, req)
						require.NoError(t, err)

						err = store.RevokeRefreshToken(context.Background(), req.ID)
						require.NoError(t, err)
					},
					expectErr: fosite.ErrInactiveToken,
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					config := &fosite.Config{
						AccessTokenLifespan:      time.Hour,
						RefreshTokenLifespan:     time.Hour,
						ScopeStrategy:            fosite.HierarchicScopeStrategy,
						AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
						RefreshTokenScopes:       []string{"offline"},
					}
					handler = &RefreshTokenGrantHandler{
						TokenRevocationStorage: store,
						RefreshTokenStrategy:   strategy,
						Config:                 config,
					}

					areq = fosite.NewAccessRequest(&fosite.DefaultSession{})
					areq.Form = url.Values{}
					c.setup(config)

					err := handler.HandleTokenEndpointRequest(context.Background(), areq)
					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error())
					} else {
						require.NoError(t, err)
					}

					if c.expect != nil {
						c.expect(t)
					}
				})
			}
		})
	}
}

func TestRefreshFlow_PopulateTokenEndpointResponse(t *testing.T) {
	var areq *fosite.AccessRequest
	var aresp *fosite.AccessResponse

	for k, strategy := range map[string]CoreStrategy{
		"hmac": &hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()

			for _, c := range []struct {
				description string
				setup       func(config *fosite.Config)
				check       func(t *testing.T)
				expectErr   error
			}{
				{
					description: "should fail because not responsible",
					expectErr:   fosite.ErrUnknownRequest,
					setup: func(config *fosite.Config) {
						areq.GrantTypes = fosite.Arguments{"313"}
					},
				},
				{
					description: "should pass",
					setup: func(config *fosite.Config) {
						areq.ID = "req-id"
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.RequestedScope = fosite.Arguments{"foo", "bar"}
						areq.GrantedScope = fosite.Arguments{"foo", "bar"}

						token, signature, err := strategy.GenerateRefreshToken(context.Background(), nil)
						require.NoError(t, err)
						require.NoError(t, store.CreateRefreshTokenSession(context.Background(), signature, areq))
						areq.Form.Add("refresh_token", token)
					},
					check: func(t *testing.T) {
						signature := strategy.RefreshTokenSignature(context.Background(), areq.Form.Get("refresh_token"))

						// The old refresh token should be deleted
						_, err := store.GetRefreshTokenSession(context.Background(), signature, nil)
						require.Error(t, err)

						assert.Equal(t, "req-id", areq.ID)
						require.NoError(t, strategy.ValidateAccessToken(context.Background(), areq, aresp.GetAccessToken()))
						require.NoError(t, strategy.ValidateRefreshToken(context.Background(), areq, aresp.ToMap()["refresh_token"].(string)))
						assert.Equal(t, "bearer", aresp.GetTokenType())
						assert.NotEmpty(t, aresp.ToMap()["expires_in"])
						assert.Equal(t, "foo bar", aresp.ToMap()["scope"])
					},
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					config := &fosite.Config{
						AccessTokenLifespan:      time.Hour,
						ScopeStrategy:            fosite.HierarchicScopeStrategy,
						AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
					}
					h := RefreshTokenGrantHandler{
						TokenRevocationStorage: store,
						RefreshTokenStrategy:   strategy,
						AccessTokenStrategy:    strategy,
						Config:                 config,
					}
					areq = fosite.NewAccessRequest(&fosite.DefaultSession{})
					aresp = fosite.NewAccessResponse()
					areq.Client = &fosite.DefaultClient{}
					areq.Form = url.Values{}

					c.setup(config)

					err := h.PopulateTokenEndpointResponse(context.Background(), areq, aresp)
					if c.expectErr != nil {
						assert.EqualError(t, err, c.expectErr.Error())
					} else {
						assert.NoError(t, err)
					}

					if c.check != nil {
						c.check(t)
					}
				})
			}
		})
	}
}
