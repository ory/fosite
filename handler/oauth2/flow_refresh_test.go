/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package oauth2

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/golang/mock/gomock"

	"github.com/ory/fosite/internal"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

func TestRefreshFlow_HandleTokenEndpointRequest(t *testing.T) {
	var areq *fosite.AccessRequest
	sess := &fosite.DefaultSession{Subject: "othersub"}

	for k, strategy := range map[string]RefreshTokenStrategy{
		"hmac": &hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {

			store := storage.NewMemoryStore()
			h := RefreshTokenGrantHandler{
				TokenRevocationStorage:   store,
				RefreshTokenStrategy:     strategy,
				AccessTokenLifespan:      time.Hour,
				RefreshTokenLifespan:     time.Hour,
				ScopeStrategy:            fosite.HierarchicScopeStrategy,
				AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
			}

			for _, c := range []struct {
				description string
				setup       func()
				expectErr   error
				expect      func(t *testing.T)
			}{
				{
					description: "should fail because not responsible",
					expectErr:   fosite.ErrUnknownRequest,
					setup: func() {
						areq.GrantTypes = fosite.Arguments{"123"}
					},
				},
				{
					description: "should fail because token invalid",
					setup: func() {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"refresh_token"}}

						areq.Form.Add("refresh_token", "some.refreshtokensig")
					},
					expectErr: fosite.ErrInvalidRequest,
				},
				{
					description: "should fail because token is valid but does not exist",
					setup: func() {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"refresh_token"}}

						token, _, err := strategy.GenerateRefreshToken(nil, nil)
						require.NoError(t, err)
						areq.Form.Add("refresh_token", token)
					},
					expectErr: fosite.ErrInvalidRequest,
				},
				{
					description: "should fail because client mismatches",
					setup: func() {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{
							ID:         "foo",
							GrantTypes: fosite.Arguments{"refresh_token"},
						}

						token, sig, err := strategy.GenerateRefreshToken(nil, nil)
						require.NoError(t, err)

						areq.Form.Add("refresh_token", token)
						err = store.CreateRefreshTokenSession(nil, sig, &fosite.Request{
							Client:       &fosite.DefaultClient{ID: ""},
							GrantedScope: []string{"offline"},
							Session:      sess,
						})
						require.NoError(t, err)
					},
					expectErr: fosite.ErrInvalidRequest,
				},
				{
					description: "should fail because offline scope has been granted but client no longer allowed to request it",
					setup: func() {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{
							ID:         "foo",
							GrantTypes: fosite.Arguments{"refresh_token"},
						}

						token, sig, err := strategy.GenerateRefreshToken(nil, nil)
						require.NoError(t, err)

						areq.Form.Add("refresh_token", token)
						err = store.CreateRefreshTokenSession(nil, sig, &fosite.Request{
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
					setup: func() {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{
							ID:         "foo",
							GrantTypes: fosite.Arguments{"refresh_token"},
							Scopes:     []string{"foo", "bar", "offline"},
						}

						token, sig, err := strategy.GenerateRefreshToken(nil, nil)
						require.NoError(t, err)

						areq.Form.Add("refresh_token", token)
						err = store.CreateRefreshTokenSession(nil, sig, &fosite.Request{
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
					},
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					areq = fosite.NewAccessRequest(&fosite.DefaultSession{})
					areq.Form = url.Values{}
					c.setup()

					err := h.HandleTokenEndpointRequest(nil, areq)
					if c.expectErr != nil {
						require.EqualError(t, errors.Cause(err), c.expectErr.Error())
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

			h := RefreshTokenGrantHandler{
				TokenRevocationStorage:   store,
				RefreshTokenStrategy:     strategy,
				AccessTokenStrategy:      strategy,
				AccessTokenLifespan:      time.Hour,
				ScopeStrategy:            fosite.HierarchicScopeStrategy,
				AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
			}
			for _, c := range []struct {
				description string
				setup       func()
				check       func()
				expectErr   error
			}{
				{
					description: "should fail because not responsible",
					expectErr:   fosite.ErrUnknownRequest,
					setup: func() {
						areq.GrantTypes = fosite.Arguments{"313"}
					},
				},
				{
					description: "should pass",
					setup: func() {
						areq.ID = "req-id"
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.RequestedScope = fosite.Arguments{"foo", "bar"}
						areq.GrantedScope = fosite.Arguments{"foo", "bar"}

						token, signature, err := strategy.GenerateRefreshToken(nil, nil)
						require.NoError(t, err)
						require.NoError(t, store.CreateRefreshTokenSession(nil, signature, areq))
						areq.Form.Add("refresh_token", token)
					},
					check: func() {
						signature := strategy.RefreshTokenSignature(areq.Form.Get("refresh_token"))

						// The old refresh token should be deleted
						_, err := store.GetRefreshTokenSession(nil, signature, nil)
						require.Error(t, err)

						assert.Equal(t, "req-id", areq.ID)
						require.NoError(t, strategy.ValidateAccessToken(nil, areq, aresp.GetAccessToken()))
						require.NoError(t, strategy.ValidateRefreshToken(nil, areq, aresp.ToMap()["refresh_token"].(string)))
						assert.Equal(t, "bearer", aresp.GetTokenType())
						assert.NotEmpty(t, aresp.ToMap()["expires_in"])
						assert.Equal(t, "foo bar", aresp.ToMap()["scope"])
					},
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					areq = fosite.NewAccessRequest(&fosite.DefaultSession{})
					aresp = fosite.NewAccessResponse()
					areq.Client = &fosite.DefaultClient{}
					areq.Form = url.Values{}

					c.setup()

					err := h.PopulateTokenEndpointResponse(nil, areq, aresp)
					if c.expectErr != nil {
						assert.EqualError(t, errors.Cause(err), c.expectErr.Error())
					} else {
						assert.NoError(t, err)
					}

					if c.check != nil {
						c.check()
					}
				})
			}
		})
	}
}

func TestRefreshFlowTransactional_PopulateTokenEndpointResponse(t *testing.T) {
	var mockTransactional *internal.MockTransactional
	var mockRevocationStore *internal.MockTokenRevocationStorage
	request := fosite.NewAccessRequest(&fosite.DefaultSession{})
	response := fosite.NewAccessResponse()
	propagatedContext := context.Background()

	// some storage implementation that has support for transactions, notice the embedded type `storage.Transactional`
	type transactionalStore struct {
		storage.Transactional
		TokenRevocationStorage
	}

	for _, testCase := range []struct {
		description string
		setup       func()
		expectError error
	}{
		{
			description: "transaction should be committed successfully if no errors occur",
			setup: func() {
				request.GrantTypes = fosite.Arguments{"refresh_token"}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateRefreshTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockTransactional.
					EXPECT().
					Commit(propagatedContext).
					Return(nil).
					Times(1)
			},
		},
		{
			description: "transaction should be rolled back if call to `GetRefreshTokenSession` results in an error",
			setup: func() {
				request.GrantTypes = fosite.Arguments{"refresh_token"}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(nil, fosite.ErrNotFound).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
		},
		{
			description: "transaction should be rolled back if call to `RevokeAccessToken` results in an error",
			setup: func() {
				request.GrantTypes = fosite.Arguments{"refresh_token"}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
		},
		{
			description: "transaction should be rolled back if call to `RevokeRefreshToken` results in an error",
			setup: func() {
				request.GrantTypes = fosite.Arguments{"refresh_token"}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshToken(propagatedContext, gomock.Any()).
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
		},
		{
			description: "transaction should be rolled back if call to `CreateAccessTokenSession` results in an error",
			setup: func() {
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
		},
		{
			description: "transaction should be rolled back if call to `CreateRefreshTokenSession` results in an error",
			setup: func() {
				request.GrantTypes = fosite.Arguments{"refresh_token"}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateRefreshTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
		},
		{
			description: "should result in a server error if transaction cannot be created",
			setup: func() {
				request.GrantTypes = fosite.Arguments{"refresh_token"}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(nil, errors.New("Could not create transaction!")).
					Times(1)
			},
			expectError: fosite.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be rolled back",
			setup: func() {
				request.GrantTypes = fosite.Arguments{"refresh_token"}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(nil, fosite.ErrNotFound).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(errors.New("Could not rollback transaction!")).
					Times(1)
			},
			expectError: fosite.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be committed",
			setup: func() {
				request.GrantTypes = fosite.Arguments{"refresh_token"}
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					GetRefreshTokenSession(propagatedContext, gomock.Any(), nil).
					Return(request, nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeAccessToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					RevokeRefreshToken(propagatedContext, gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockRevocationStore.
					EXPECT().
					CreateRefreshTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockTransactional.
					EXPECT().
					Commit(propagatedContext).
					Return(errors.New("Could not commit transaction!")).
					Times(1)
			},
			expectError: fosite.ErrServerError,
		},
	} {
		t.Run(fmt.Sprintf("scenario=%s", testCase.description), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockTransactional = internal.NewMockTransactional(ctrl)
			mockRevocationStore = internal.NewMockTokenRevocationStorage(ctrl)
			testCase.setup()

			handler := RefreshTokenGrantHandler{
				// Notice how we are passing in a store that has support for transactions!
				TokenRevocationStorage: transactionalStore{
					mockTransactional,
					mockRevocationStore,
				},
				AccessTokenStrategy:      &hmacshaStrategy,
				RefreshTokenStrategy:     &hmacshaStrategy,
				AccessTokenLifespan:      time.Hour,
				ScopeStrategy:            fosite.HierarchicScopeStrategy,
				AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
			}

			if err := handler.PopulateTokenEndpointResponse(propagatedContext, request, response); testCase.expectError != nil {
				assert.EqualError(t, errors.Cause(err), testCase.expectError.Error())
			}
		})
	}
}
