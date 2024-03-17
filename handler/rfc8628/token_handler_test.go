// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite/internal"

	"github.com/patrickmn/go-cache"

	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/hmac"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var hmacshaStrategy = oauth2.NewHMACSHAStrategy(
	&hmac.HMACStrategy{Config: &fosite.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
	&fosite.Config{
		AccessTokenLifespan:   time.Hour * 24,
		AuthorizeCodeLifespan: time.Hour * 24,
	},
)

var RFC8628HMACSHAStrategy = DefaultDeviceStrategy{
	Enigma: &hmac.HMACStrategy{Config: &fosite.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
	RateLimiterCache: cache.New(
		time.Hour*12,
		time.Hour*24,
	),
	Config: &fosite.Config{
		DeviceAndUserCodeLifespan: time.Hour * 24,
	},
}

func TestDeviceUserCode_PopulateTokenEndpointResponse(t *testing.T) {
	for k, strategy := range map[string]struct {
		oauth2.CoreStrategy
		RFC8628CodeStrategy
	}{
		"hmac": {hmacshaStrategy, &RFC8628HMACSHAStrategy},
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()

			var h oauth2.GenericCodeTokenEndpointHandler
			for _, c := range []struct {
				areq        *fosite.AccessRequest
				description string
				setup       func(t *testing.T, areq *fosite.AccessRequest, config *fosite.Config)
				check       func(t *testing.T, aresp *fosite.AccessResponse)
				expectErr   error
			}{
				{
					description: "should fail because not responsible",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"123"},
					},
					expectErr: fosite.ErrUnknownRequest,
				},
				{
					description: "should fail because device code cannot be retrieved",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Form: url.Values{},
							Client: &fosite.DefaultClient{
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, config *fosite.Config) {
						code, _, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						areq.Form.Set("device_code", code)
					},
					expectErr: fosite.ErrServerError,
				},
				{
					description: "should pass with offline scope and refresh token",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Form: url.Values{},
							Client: &fosite.DefaultClient{
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
							},
							GrantedScope: fosite.Arguments{"foo", "offline"},
							Session:      &fosite.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, config *fosite.Config) {
						code, signature, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						areq.Form.Add("device_code", code)

						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), signature, areq))
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
					description: "should pass with refresh token always provided",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Form: url.Values{},
							Client: &fosite.DefaultClient{
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
							},
							GrantedScope: fosite.Arguments{"foo"},
							Session:      &fosite.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, config *fosite.Config) {
						config.RefreshTokenScopes = []string{}
						code, signature, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						areq.Form.Add("device_code", code)

						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), signature, areq))
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
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Form: url.Values{},
							Client: &fosite.DefaultClient{
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							GrantedScope: fosite.Arguments{"foo"},
							Session:      &fosite.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, config *fosite.Config) {
						code, sig, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						areq.Form.Add("device_code", code)

						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), sig, areq))
					},
					check: func(t *testing.T, aresp *fosite.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.Empty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Equal(t, "foo", aresp.GetExtra("scope"))
					},
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					config := &fosite.Config{
						ScopeStrategy:            fosite.HierarchicScopeStrategy,
						AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
						AccessTokenLifespan:      time.Minute,
						RefreshTokenScopes:       []string{"offline"},
					}
					h = oauth2.GenericCodeTokenEndpointHandler{
						AccessRequestValidator: &DeviceAccessRequestValidator{},
						CodeHandler: &DeviceCodeHandler{
							DeviceRateLimitStrategy: strategy,
							DeviceCodeStrategy:      strategy,
						},
						SessionHandler: &DeviceSessionHandler{
							DeviceCodeStorage: store,
						},
						AccessTokenStrategy:    strategy.CoreStrategy,
						RefreshTokenStrategy:   strategy.CoreStrategy,
						Config:                 config,
						CoreStorage:            store,
						TokenRevocationStorage: store,
					}

					if c.setup != nil {
						c.setup(t, c.areq, config)
					}

					aresp := fosite.NewAccessResponse()
					err := h.PopulateTokenEndpointResponse(context.TODO(), c.areq, aresp)

					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error(), "%+v", err)
					} else {
						require.NoError(t, err, "%+v", err)
					}

					if c.check != nil {
						c.check(t, aresp)
					}
				})
			}
		})
	}
}

func TestDeviceUserCode_HandleTokenEndpointRequest(t *testing.T) {
	for k, strategy := range map[string]struct {
		oauth2.CoreStrategy
		RFC8628CodeStrategy
	}{
		"hmac": {hmacshaStrategy, &RFC8628HMACSHAStrategy},
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()

			h := oauth2.GenericCodeTokenEndpointHandler{
				AccessRequestValidator: &DeviceAccessRequestValidator{},
				CodeHandler: &DeviceCodeHandler{
					DeviceRateLimitStrategy: strategy,
					DeviceCodeStrategy:      strategy,
				},
				SessionHandler: &DeviceSessionHandler{
					DeviceCodeStorage: store,
				},
				CoreStorage:          store,
				AccessTokenStrategy:  strategy.CoreStrategy,
				RefreshTokenStrategy: strategy.CoreStrategy,
				Config: &fosite.Config{
					ScopeStrategy:             fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:  fosite.DefaultAudienceMatchingStrategy,
					DeviceAndUserCodeLifespan: time.Minute,
				},
			}
			for i, c := range []struct {
				description string
				areq        *fosite.AccessRequest
				authreq     *fosite.DeviceRequest
				setup       func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.DeviceRequest)
				check       func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.DeviceRequest)
				expectErr   error
			}{
				{
					description: "should fail because not responsible",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"12345678"},
					},
					expectErr: fosite.ErrUnknownRequest,
				},
				{
					description: "should fail because client is not granted the correct grant type",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					expectErr: fosite.ErrUnauthorizedClient,
				},
				{
					description: "should fail because device code could not be retrieved",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.DeviceRequest) {
						deviceCode, _, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						areq.Form = url.Values{"device_code": {deviceCode}}
					},
					expectErr: fosite.ErrInvalidGrant,
				},
				{
					description: "should fail because device code has expired",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Form: url.Values{},
							Client: &fosite.DefaultClient{
								ID:         "foo",
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							GrantedScope: fosite.Arguments{"foo", "offline"},
							Session:      &fosite.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					authreq: &fosite.DeviceRequest{
						Request: fosite.Request{
							Client: &fosite.DefaultClient{ID: "foo", GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session: &fosite.DefaultSession{
								ExpiresAt: map[fosite.TokenType]time.Time{
									fosite.DeviceCode: time.Now().Add(-time.Hour).UTC(),
								},
							},
							RequestedAt: time.Now().Add(-2 * time.Hour).UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.DeviceRequest) {
						code, signature, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						areq.Form.Add("device_code", code)

						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), signature, authreq))
					},
					expectErr: fosite.ErrDeviceExpiredToken,
				},
				{
					description: "should fail because client mismatch",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &fosite.DeviceRequest{
						Request: fosite.Request{
							Client: &fosite.DefaultClient{ID: "bar"},
							Session: &fosite.DefaultSession{
								ExpiresAt: map[fosite.TokenType]time.Time{
									fosite.DeviceCode: time.Now().Add(time.Hour).UTC(),
								},
							},
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.DeviceRequest) {
						token, signature, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						areq.Form = url.Values{"device_code": {token}}

						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), signature, authreq))
					},
					expectErr: fosite.ErrInvalidGrant,
				},
				{
					description: "should pass",
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &fosite.DeviceRequest{
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.DeviceRequest) {
						token, signature, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)

						areq.Form = url.Values{"device_code": {token}}
						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), signature, authreq))
					},
				},
			} {
				t.Run(fmt.Sprintf("case=%d/description=%s", i, c.description), func(t *testing.T) {
					if c.setup != nil {
						c.setup(t, c.areq, c.authreq)
					}

					t.Logf("Processing %+v", c.areq.Client)

					err := h.HandleTokenEndpointRequest(context.Background(), c.areq)
					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error(), "%+v", err)
					} else {
						require.NoError(t, err, "%+v", err)
						if c.check != nil {
							c.check(t, c.areq, c.authreq)
						}
					}
				})
			}
		})
	}
}

func TestDeviceUserCodeTransactional_HandleTokenEndpointRequest(t *testing.T) {
	var mockTransactional *internal.MockTransactional
	var mockCoreStore *internal.MockCoreStorage
	var mockDeviceCodeStore *internal.MockDeviceCodeStorage
	var mockDeviceRateLimitStrategy *internal.MockDeviceRateLimitStrategy
	strategy := hmacshaStrategy
	deviceStrategy := RFC8628HMACSHAStrategy
	request := &fosite.AccessRequest{
		GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
		Request: fosite.Request{
			Client: &fosite.DefaultClient{
				GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
			},
			GrantedScope: fosite.Arguments{"offline"},
			Session:      &fosite.DefaultSession{},
			RequestedAt:  time.Now().UTC(),
		},
	}
	token, _, err := deviceStrategy.GenerateDeviceCode(context.Background())
	require.NoError(t, err)
	request.Form = url.Values{"device_code": {token}}
	response := fosite.NewAccessResponse()
	propagatedContext := context.Background()

	// some storage implementation that has support for transactions, notice the embedded type `storage.Transactional`
	type coreTransactionalStore struct {
		storage.Transactional
		oauth2.CoreStorage
	}

	type deviceTransactionalStore struct {
		storage.Transactional
		DeviceCodeStorage
	}

	for _, testCase := range []struct {
		description string
		setup       func()
		expectError error
	}{
		{
			description: "transaction should be committed successfully if no errors occur",
			setup: func() {
				mockDeviceCodeStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(request, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockDeviceCodeStore.
					EXPECT().
					InvalidateDeviceCodeSession(gomock.Any(), gomock.Any()).
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
			description: "transaction should be rolled back if `InvalidateDeviceCodeSession` returns an error",
			setup: func() {
				mockDeviceCodeStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(request, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockDeviceCodeStore.
					EXPECT().
					InvalidateDeviceCodeSession(gomock.Any(), gomock.Any()).
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
				mockDeviceCodeStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(request, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockDeviceCodeStore.
					EXPECT().
					InvalidateDeviceCodeSession(gomock.Any(), gomock.Any()).
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
				mockDeviceCodeStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(request, nil).
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
				mockDeviceCodeStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(request, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockDeviceCodeStore.
					EXPECT().
					InvalidateDeviceCodeSession(gomock.Any(), gomock.Any()).
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
				mockDeviceCodeStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(request, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockDeviceCodeStore.
					EXPECT().
					InvalidateDeviceCodeSession(gomock.Any(), gomock.Any()).
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
	} {
		t.Run(fmt.Sprintf("scenario=%s", testCase.description), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockTransactional = internal.NewMockTransactional(ctrl)
			mockCoreStore = internal.NewMockCoreStorage(ctrl)
			mockDeviceCodeStore = internal.NewMockDeviceCodeStorage(ctrl)
			mockDeviceRateLimitStrategy = internal.NewMockDeviceRateLimitStrategy(ctrl)
			mockDeviceRateLimitStrategy.EXPECT().ShouldRateLimit(gomock.Any(), gomock.Any()).Return(false).Times(1)
			testCase.setup()

			handler := oauth2.GenericCodeTokenEndpointHandler{
				AccessRequestValidator: &DeviceAccessRequestValidator{},
				CodeHandler: &DeviceCodeHandler{
					DeviceRateLimitStrategy: mockDeviceRateLimitStrategy,
					DeviceCodeStrategy:      &deviceStrategy,
				},
				SessionHandler: &DeviceSessionHandler{
					DeviceCodeStorage: deviceTransactionalStore{
						mockTransactional,
						mockDeviceCodeStore,
					},
				},
				CoreStorage: coreTransactionalStore{
					mockTransactional,
					mockCoreStore,
				},
				AccessTokenStrategy:  strategy,
				RefreshTokenStrategy: strategy,
				Config: &fosite.Config{
					ScopeStrategy:             fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:  fosite.DefaultAudienceMatchingStrategy,
					DeviceAndUserCodeLifespan: time.Minute,
				},
			}

			if err = handler.PopulateTokenEndpointResponse(propagatedContext, request, response); testCase.expectError != nil {
				assert.EqualError(t, err, testCase.expectError.Error())
			}
		})
	}
}
