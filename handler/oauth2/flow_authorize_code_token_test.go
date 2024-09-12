// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	gomock "go.uber.org/mock/gomock"

	"github.com/ory/fosite/internal"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeCode_PopulateTokenEndpointResponse(t *testing.T) {
	for k, strategy := range map[string]CoreStrategy{
		"hmac": hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()

			testCases := []struct {
				description string
				areq        *fosite.AccessRequest
				authreq     *fosite.AuthorizeRequest
				setup       func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.AuthorizeRequest, config *fosite.Config)
				check       func(t *testing.T, aresp *fosite.AccessResponse)
				expectErr   error
			}{
				{
					description: "should fail because not responsible for handling the request",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"implicit"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								GrantTypes: fosite.Arguments{"authorization_code"},
							},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					expectErr: fosite.ErrUnknownRequest,
				},
				{
					description: "should fail because authorization code cannot be retrieved",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"authorization_code"},
						Request: fosite.Request{
							Form: url.Values{},
							Client: &fosite.DefaultClient{
								GrantTypes: fosite.Arguments{"authorization_code"},
							},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, _ *fosite.AuthorizeRequest, _ *fosite.Config) {
						code, _, err := strategy.GenerateAuthorizeCode(context.Background(), nil)
						require.NoError(t, err)
						areq.Form.Set("code", code)
					},
					expectErr: fosite.ErrServerError,
				},
				{
					description: "should pass with offline scope and refresh token grant type",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"authorization_code"},
						Request: fosite.Request{
							Form: url.Values{},
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: fosite.Arguments{"authorization_code", "refresh_token"},
							},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &fosite.AuthorizeRequest{
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: []string{"authorization_code"},
							},
							RequestedScope: fosite.Arguments{"foo", "bar", "offline"},
							GrantedScope:   fosite.Arguments{"foo", "offline"},
							Session:        &fosite.DefaultSession{},
							RequestedAt:    time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.AuthorizeRequest, _ *fosite.Config) {
						code, signature, err := strategy.GenerateAuthorizeCode(context.Background(), nil)
						require.NoError(t, err)
						areq.Form.Set("code", code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.Background(), signature, authreq))
					},
					check: func(t *testing.T, aresp *fosite.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.NotEmpty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Equal(t, "foo offline", aresp.GetExtra("scope"))
					},
				},
				{
					description: "should pass with refresh token grant type",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"authorization_code"},
						Request: fosite.Request{
							Form: url.Values{},
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: fosite.Arguments{"authorization_code", "refresh_token"},
							},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &fosite.AuthorizeRequest{
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: []string{"authorization_code"},
							},
							RequestedScope: fosite.Arguments{"foo", "bar"},
							GrantedScope:   fosite.Arguments{"foo"},
							Session:        &fosite.DefaultSession{},
							RequestedAt:    time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.AuthorizeRequest, config *fosite.Config) {
						config.RefreshTokenScopes = []string{}
						code, signature, err := strategy.GenerateAuthorizeCode(context.Background(), nil)
						require.NoError(t, err)
						areq.Form.Set("code", code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.Background(), signature, authreq))
					},
					check: func(t *testing.T, aresp *fosite.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.NotEmpty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Equal(t, "foo", aresp.GetExtra("scope"))
					},
				},
				{
					description: "pass and response should not have refresh token",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"authorization_code"},
						Request: fosite.Request{
							Form: url.Values{},
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: fosite.Arguments{"authorization_code"},
							},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &fosite.AuthorizeRequest{
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: []string{"authorization_code"},
							},
							RequestedScope: fosite.Arguments{"foo", "bar"},
							GrantedScope:   fosite.Arguments{"foo"},
							Session:        &fosite.DefaultSession{},
							RequestedAt:    time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.AuthorizeRequest, _ *fosite.Config) {
						code, sig, err := strategy.GenerateAuthorizeCode(context.Background(), nil)
						require.NoError(t, err)
						areq.Form.Set("code", code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.Background(), sig, authreq))
					},
					check: func(t *testing.T, aresp *fosite.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.Empty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Equal(t, "foo", aresp.GetExtra("scope"))
					},
				},
			}

			for _, testCase := range testCases {
				t.Run("case="+testCase.description, func(t *testing.T) {
					config := &fosite.Config{
						ScopeStrategy:            fosite.HierarchicScopeStrategy,
						AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
						AccessTokenLifespan:      time.Minute,
						RefreshTokenScopes:       []string{"offline"},
					}
					h := GenericCodeTokenEndpointHandler{
						AccessRequestValidator: &AuthorizeExplicitGrantAccessRequestValidator{},
						CodeHandler: &AuthorizeCodeHandler{
							AuthorizeCodeStrategy: strategy,
						},
						SessionHandler: &AuthorizeExplicitGrantSessionHandler{
							AuthorizeCodeStorage: store,
						},
						AccessTokenStrategy:  strategy,
						RefreshTokenStrategy: strategy,
						CoreStorage:          store,
						Config:               config,
					}

					if testCase.setup != nil {
						testCase.setup(t, testCase.areq, testCase.authreq, config)
					}

					aresp := fosite.NewAccessResponse()
					err := h.PopulateTokenEndpointResponse(context.Background(), testCase.areq, aresp)

					if testCase.expectErr != nil {
						require.EqualError(t, err, testCase.expectErr.Error(), "%+v", err)
					} else {
						require.NoError(t, err, "%+v", err)
					}

					if testCase.check != nil {
						testCase.check(t, aresp)
					}
				})
			}
		})
	}
}

func TestAuthorizeCode_HandleTokenEndpointRequest(t *testing.T) {
	for k, strategy := range map[string]CoreStrategy{
		"hmac": hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()
			config := &fosite.Config{
				ScopeStrategy:            fosite.HierarchicScopeStrategy,
				AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
				AuthorizeCodeLifespan:    time.Minute,
			}
			h := GenericCodeTokenEndpointHandler{
				AccessRequestValidator: &AuthorizeExplicitGrantAccessRequestValidator{},
				CodeHandler: &AuthorizeCodeHandler{
					AuthorizeCodeStrategy: strategy,
				},
				SessionHandler: &AuthorizeExplicitGrantSessionHandler{
					AuthorizeCodeStorage: store,
				},
				TokenRevocationStorage: store,
				Config:                 config,
			}

			testCases := []struct {
				description string
				areq        *fosite.AccessRequest
				authreq     *fosite.AuthorizeRequest
				setup       func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.AuthorizeRequest)
				check       func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.AuthorizeRequest)
				expectErr   error
			}{
				{
					description: "should fail because not responsible for handling the request",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"implicit"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: []string{"authorization_code"},
							},
							Form:        url.Values{"redirect_uri": []string{"request-redir"}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					expectErr: fosite.ErrUnknownRequest,
				},
				{
					description: "should fail because client is not granted the correct grant type",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"authorization_code"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: []string{""},
							},
							Form:        url.Values{"redirect_uri": []string{"request-redir"}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					expectErr: fosite.ErrUnauthorizedClient,
				},
				{
					description: "should fail because authorization code cannot be retrieved",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"authorization_code"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: []string{"authorization_code"},
							},
							Form:        url.Values{"redirect_uri": []string{"request-redir"}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.AuthorizeRequest) {
						code, _, err := strategy.GenerateAuthorizeCode(context.Background(), nil)
						require.NoError(t, err)
						areq.Form.Set("code", code)
					},
					expectErr: fosite.ErrInvalidGrant,
				},
				{
					description: "should fail because authorization code is expired",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"authorization_code"},
						Request: fosite.Request{
							Form: url.Values{
								"code":         {"foo.bar"},
								"redirect_uri": []string{"request-redir"},
							},
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: []string{"authorization_code"},
							},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &fosite.AuthorizeRequest{
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: []string{"authorization_code"},
							},
							Form:           url.Values{"redirect_uri": []string{"request-redir"}},
							RequestedScope: fosite.Arguments{"foo"},
							GrantedScope:   fosite.Arguments{"foo"},
							Session: &fosite.DefaultSession{
								ExpiresAt: map[fosite.TokenType]time.Time{
									fosite.AuthorizeCode: time.Now().Add(-time.Hour).UTC(),
								},
							},
							RequestedAt: time.Now().Add(-2 * time.Hour).UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.AuthorizeRequest) {
						code, signature, err := strategy.GenerateAuthorizeCode(context.Background(), nil)
						require.NoError(t, err)
						areq.Form.Set("code", code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.Background(), signature, authreq))
					},
					expectErr: fosite.ErrTokenExpired,
				},
				{
					description: "should fail because client mismatch",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"authorization_code"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: []string{"authorization_code"},
							},
							Form:        url.Values{"redirect_uri": []string{"request-redir"}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &fosite.AuthorizeRequest{
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "bar",
								GrantTypes: []string{"authorization_code"},
							},
							Form:           url.Values{"redirect_uri": []string{"request-redir"}},
							RequestedScope: fosite.Arguments{"foo"},
							GrantedScope:   fosite.Arguments{"foo"},
							Session: &fosite.DefaultSession{
								ExpiresAt: map[fosite.TokenType]time.Time{
									fosite.AuthorizeCode: time.Now().Add(time.Hour).UTC(),
								},
							},
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.AuthorizeRequest) {
						code, signature, err := strategy.GenerateAuthorizeCode(context.Background(), nil)
						require.NoError(t, err)
						areq.Form.Set("code", code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.Background(), signature, authreq))
					},
					expectErr: fosite.ErrInvalidGrant,
				},
				{
					description: "should fail because redirect uri was set during /authorize call, but not in /token call",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"authorization_code"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: []string{"authorization_code"},
							},
							Form:        url.Values{},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &fosite.AuthorizeRequest{
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: []string{"authorization_code"},
							},
							Form:           url.Values{"redirect_uri": []string{"request-redir"}},
							RequestedScope: fosite.Arguments{"foo"},
							GrantedScope:   fosite.Arguments{"foo"},
							Session: &fosite.DefaultSession{
								ExpiresAt: map[fosite.TokenType]time.Time{
									fosite.AuthorizeCode: time.Now().Add(time.Hour).UTC(),
								},
							},
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.AuthorizeRequest) {
						code, signature, err := strategy.GenerateAuthorizeCode(context.Background(), nil)
						require.NoError(t, err)
						areq.Form.Set("code", code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.Background(), signature, authreq))
					},
					expectErr: fosite.ErrInvalidGrant,
				},
				{
					description: "should pass",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"authorization_code"},
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: []string{"authorization_code"},
							},
							Form:        url.Values{"redirect_uri": []string{"request-redir"}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &fosite.AuthorizeRequest{
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: []string{"authorization_code"},
							},
							Form:           url.Values{"redirect_uri": []string{"request-redir"}},
							RequestedScope: fosite.Arguments{"foo"},
							GrantedScope:   fosite.Arguments{"foo"},
							Session:        &fosite.DefaultSession{},
							RequestedAt:    time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.AuthorizeRequest) {
						code, signature, err := strategy.GenerateAuthorizeCode(context.Background(), nil)
						require.NoError(t, err)
						areq.Form.Set("code", code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.Background(), signature, authreq))
					},
				},
				{
					description: "should fail because code has been used already",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"authorization_code"},
						Request: fosite.Request{
							Form: url.Values{"redirect_uri": []string{"request-redir"}},
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: fosite.Arguments{"authorization_code"},
							},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &fosite.AuthorizeRequest{
						Request: fosite.Request{
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: []string{"authorization_code"},
							},
							Form:           url.Values{"redirect_uri": []string{"request-redir"}},
							RequestedScope: fosite.Arguments{"foo"},
							GrantedScope:   fosite.Arguments{"foo"},
							Session:        &fosite.DefaultSession{},
							RequestedAt:    time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.AuthorizeRequest) {
						code, signature, err := strategy.GenerateAuthorizeCode(context.Background(), nil)
						require.NoError(t, err)
						areq.Form.Set("code", code)

						require.NoError(t, store.CreateAuthorizeCodeSession(context.Background(), signature, authreq))
						require.NoError(t, store.InvalidateAuthorizeCodeSession(context.Background(), signature))
					},
					expectErr: fosite.ErrInvalidGrant,
				},
			}

			for i, testCase := range testCases {
				t.Run(fmt.Sprintf("case=%d/description=%s", i, testCase.description), func(t *testing.T) {
					if testCase.setup != nil {
						testCase.setup(t, testCase.areq, testCase.authreq)
					}

					t.Logf("Processing %+v", testCase.areq.Client)

					err := h.HandleTokenEndpointRequest(context.Background(), testCase.areq)
					if testCase.expectErr != nil {
						require.EqualError(t, err, testCase.expectErr.Error(), "%+v", err)
					} else {
						require.NoError(t, err, "%+v", err)
						if testCase.check != nil {
							testCase.check(t, testCase.areq, testCase.authreq)
						}
					}
				})
			}
		})
	}
}

func TestAuthorizeCodeTransactional_HandleTokenEndpointRequest(t *testing.T) {
	var mockTransactional *internal.MockTransactional
	var mockCoreStore *internal.MockCoreStorage
	var mockAuthorizeStore *internal.MockAuthorizeCodeStorage
	strategy := hmacshaStrategy

	authreq := &fosite.AuthorizeRequest{
		Request: fosite.Request{
			Client: &fosite.DefaultClient{
				ID:         "foo",
				GrantTypes: []string{"authorization_code"},
			},
			RequestedScope: fosite.Arguments{"foo", "offline"},
			GrantedScope:   fosite.Arguments{"foo", "offline"},
			Session:        &fosite.DefaultSession{},
			RequestedAt:    time.Now().UTC(),
		},
	}

	areq := &fosite.AccessRequest{
		GrantTypes: fosite.Arguments{"authorization_code"},
		Request: fosite.Request{
			Client: &fosite.DefaultClient{
				GrantTypes: fosite.Arguments{"authorization_code", "refresh_token"},
			},
			Session:     &fosite.DefaultSession{},
			RequestedAt: time.Now().UTC(),
		},
	}
	aresp := fosite.NewAccessResponse()
	propagatedContext := context.Background()

	code, _, err := strategy.GenerateAuthorizeCode(context.Background(), nil)
	require.NoError(t, err)
	areq.Form = url.Values{"code": {code}}

	// some storage implementation that has support for transactions, notice the embedded type `storage.Transactional`
	type transactionalStore struct {
		storage.Transactional
		CoreStorage
	}

	type authorizeTransactionalStore struct {
		storage.Transactional
		AuthorizeCodeStorage
	}

	testCases := []struct {
		description string
		setup       func()
		expectError error
	}{
		{
			description: "transaction should be committed successfully if no errors occur",
			setup: func() {
				mockAuthorizeStore.
					EXPECT().
					GetAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(authreq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockAuthorizeStore.
					EXPECT().
					InvalidateAuthorizeCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
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
			description: "transaction should be rolled back if `InvalidateAuthorizeCodeSession` returns an error",
			setup: func() {
				mockAuthorizeStore.
					EXPECT().
					GetAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(authreq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockAuthorizeStore.
					EXPECT().
					InvalidateAuthorizeCodeSession(gomock.Any(), gomock.Any()).
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: fosite.ErrServerError,
		},
		{
			description: "transaction should be rolled back if `CreateAccessTokenSession` returns an error",
			setup: func() {
				mockAuthorizeStore.
					EXPECT().
					GetAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(authreq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockAuthorizeStore.
					EXPECT().
					InvalidateAuthorizeCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
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
			expectError: fosite.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be created",
			setup: func() {
				mockAuthorizeStore.
					EXPECT().
					GetAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(authreq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(nil, errors.New("Whoops, unable to create transaction!"))
			},
			expectError: fosite.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be rolled back",
			setup: func() {
				mockAuthorizeStore.
					EXPECT().
					GetAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(authreq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockAuthorizeStore.
					EXPECT().
					InvalidateAuthorizeCodeSession(gomock.Any(), gomock.Any()).
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(errors.New("Whoops, unable to rollback transaction!")).
					Times(1)
			},
			expectError: fosite.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be committed",
			setup: func() {
				mockAuthorizeStore.
					EXPECT().
					GetAuthorizeCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(authreq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockAuthorizeStore.
					EXPECT().
					InvalidateAuthorizeCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateRefreshTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockTransactional.
					EXPECT().
					Commit(propagatedContext).
					Return(errors.New("Whoops, unable to commit transaction!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: fosite.ErrServerError,
		},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("scenario=%s", testCase.description), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockTransactional = internal.NewMockTransactional(ctrl)
			mockCoreStore = internal.NewMockCoreStorage(ctrl)
			mockAuthorizeStore = internal.NewMockAuthorizeCodeStorage(ctrl)
			testCase.setup()

			config := &fosite.Config{
				ScopeStrategy:            fosite.HierarchicScopeStrategy,
				AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
				AuthorizeCodeLifespan:    time.Minute,
			}
			h := GenericCodeTokenEndpointHandler{
				AccessRequestValidator: &AuthorizeExplicitGrantAccessRequestValidator{},
				CodeHandler: &AuthorizeCodeHandler{
					AuthorizeCodeStrategy: strategy,
				},
				SessionHandler: &AuthorizeExplicitGrantSessionHandler{
					AuthorizeCodeStorage: authorizeTransactionalStore{
						mockTransactional,
						mockAuthorizeStore,
					},
				},
				CoreStorage: transactionalStore{
					mockTransactional,
					mockCoreStore,
				},
				AccessTokenStrategy:  strategy,
				RefreshTokenStrategy: strategy,
				Config:               config,
			}

			if err := h.PopulateTokenEndpointResponse(propagatedContext, areq, aresp); testCase.expectError != nil {
				assert.EqualError(t, err, testCase.expectError.Error())
			}
		})
	}
}
