// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	fositeOAuth2 "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

func TestTokenExchange_HandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	teStore := internal.NewMockRFC8693Storage(ctrl)
	atStore := internal.NewMockAccessTokenStorage(ctrl)
	rtStore := internal.NewMockRefreshTokenGrantStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	areq := internal.NewMockAccessRequester(ctrl)
	defer ctrl.Finish()

	h := Handler{
		Storage: teStore,
		Config:  &fosite.Config{},
		HandleHelper: &fositeOAuth2.HandleHelper{
			AccessTokenStorage:  atStore,
			AccessTokenStrategy: chgen,
			Config: &fosite.Config{
				AccessTokenLifespan: time.Hour,
			},
		},
		RefreshTokenStorage: rtStore,
	}

	for _, c := range []struct {
		name      string
		mock      func()
		req       *http.Request
		expectErr error
	}{
		{
			name:      "should fail because granttype is missing",
			expectErr: fosite.ErrUnknownRequest,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{""})
			},
		},
		{
			name:      "should fail because invalid client_id",
			expectErr: fosite.ErrUnauthorizedClient,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{})
			},
		},
		{
			name:      "should fail because grant_type is not valid",
			expectErr: fosite.ErrUnauthorizedClient,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					ID:         "client",
					GrantTypes: fosite.Arguments{""},
				})
			},
		},
		{
			name:      "should fail because no subject_token",
			expectErr: fosite.ErrInvalidRequest,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					ID:         "client",
					GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"},
				})
				areq.EXPECT().GetRequestForm().Return(url.Values{
					"subject_token": []string{""},
				})
			},
		},
		{
			name:      "should fail because unsupported subject_token_type",
			expectErr: fosite.ErrInvalidRequest,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					ID:         "client",
					GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"},
				})
				areq.EXPECT().GetRequestForm().Return(url.Values{
					"subject_token":      []string{"subject_token"},
					"subject_token_type": []string{"unsupported_subject_token_type"},
				})
			},
		},
		{
			name:      "should fail because scope not valid",
			expectErr: fosite.ErrInvalidScope,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					ID:         "client",
					GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"},
					Scopes:     []string{"none"},
				})
				areq.EXPECT().GetRequestForm().Return(url.Values{
					"subject_token":        []string{"subject_token"},
					"subject_token_type":   []string{"urn:ietf:params:oauth:token-type:access_token"},
					"requested_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
				})
				areq.EXPECT().GetRequestedScopes().Return([]string{"foo"})
			},
		},
		{
			name: "should pass as AT",
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					ID:         "client",
					GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"},
					Scopes:     []string{"foo"},
				})
				areq.EXPECT().GetRequestForm().Return(url.Values{
					"subject_token":        []string{"subject_token"},
					"subject_token_type":   []string{"urn:ietf:params:oauth:token-type:access_token"},
					"requested_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
				})

				// scope and audience.
				areq.EXPECT().GetRequestedScopes().Return([]string{"foo"})
				areq.EXPECT().GrantScope("foo")
				areq.EXPECT().GetRequestedAudience().Return([]string{})
				areq.EXPECT().GetRequestedAudience().Return([]string{})
				chgen.EXPECT().AccessTokenSignature(gomock.Any(), gomock.Any()).Return("signature")

				// original request.
				ar := internal.NewMockAccessRequester(ctrl)
				atStore.EXPECT().GetAccessTokenSession(gomock.Any(), "signature", nil).Return(ar, nil)
				chgen.EXPECT().ValidateAccessToken(gomock.Any(), ar, gomock.Any()).Return(nil)

				teStore.EXPECT().GetAllowedClientIDs(gomock.Any(), "client").Return([]string{"client2"}, nil)
				ar.EXPECT().GetClient().Return(&fosite.DefaultClient{
					ID: "client2",
				})
				ar.EXPECT().GetSession().Return(new(fosite.DefaultSession))
				areq.EXPECT().SetSession(gomock.Any())
			},
		},
		{
			name:      "should fail because of different key",
			expectErr: fosite.ErrInvalidRequest,
			mock: func() {
				// ID Token JWT.
				key := []byte("aabbbbccccddddddd")
				token := jwt.Token{
					Header: map[string]interface{}{
						"kid": "12asd4q34daf",
					},
					Claims: jwt.MapClaims{
						"sub": "foo",
						"exp": time.Now().Add(time.Hour).Unix(),
						"iss": "bar",
						"jti": "12345",
						"aud": "token-url",
					},
					Method: jose.HS256,
				}
				tokenString, err := token.SignedString(key)
				require.NoError(t, err)

				// request.
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					ID:         "client",
					GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"},
					Scopes:     []string{"foo"},
				})
				areq.EXPECT().GetRequestForm().Return(url.Values{
					"subject_token":        []string{tokenString},
					"subject_token_type":   []string{"urn:ietf:params:oauth:token-type:id_token"},
					"requested_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
				})

				// scope and audience.
				areq.EXPECT().GetRequestedScopes().Return([]string{"foo"})
				areq.EXPECT().GrantScope("foo")
				areq.EXPECT().GetRequestedAudience().Return([]string{})
				areq.EXPECT().GetRequestedAudience().Return([]string{})

				// verify IDToken.
				teStore.EXPECT().GetIDTokenPublicKey(gomock.Any(), "bar", "12asd4q34daf").Return(&jose.JSONWebKey{
					Key: []byte("differnet_key"),
				}, nil)
			},
		},
		{
			name: "should pass as JWT",
			mock: func() {
				// ID Token JWT.
				key := []byte("aaabbbbcccddd")
				token := jwt.Token{
					Header: map[string]interface{}{
						"kid": "12asd4q34daf",
					},
					Claims: jwt.MapClaims{
						"sub": "foo",
						"exp": time.Now().Add(time.Hour).Unix(),
						"iss": "bar",
						"jti": "12345",
						"aud": "token-url",
					},
					Method: jose.HS256,
				}
				tokenString, err := token.SignedString(key)
				require.NoError(t, err)

				// request.
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					ID:         "client",
					GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"},
					Scopes:     []string{"foo"},
				})
				areq.EXPECT().GetRequestForm().Return(url.Values{
					"subject_token":        []string{tokenString},
					"subject_token_type":   []string{"urn:ietf:params:oauth:token-type:id_token"},
					"requested_token_type": []string{"urn:ietf:params:oauth:token-type:access_token"},
				})

				// scope and audience.
				areq.EXPECT().GetRequestedScopes().Return([]string{"foo"})
				areq.EXPECT().GrantScope("foo")
				areq.EXPECT().GetRequestedAudience().Return([]string{})
				areq.EXPECT().GetRequestedAudience().Return([]string{})

				// verify IDToken.
				teStore.EXPECT().GetIDTokenPublicKey(gomock.Any(), "bar", "12asd4q34daf").Return(&jose.JSONWebKey{
					Key: key,
				}, nil)
				teStore.EXPECT().GetImpersonateSubject(gomock.Any(), gomock.Any(), gomock.Any()).Return("client", nil)

				areq.EXPECT().SetSession(gomock.Any())
				areq.EXPECT().GetSession().Return(new(fosite.DefaultSession))
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.mock()
			err := h.HandleTokenEndpointRequest(context.TODO(), areq)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTokenExchange_PopulateTokenEndpointResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	atStore := internal.NewMockAccessTokenStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)

	areq := fosite.NewAccessRequest(new(fosite.DefaultSession))
	aresp := fosite.NewAccessResponse()
	rtStrategy := internal.NewMockRefreshTokenStrategy(ctrl)
	rtStore := internal.NewMockRefreshTokenGrantStorage(ctrl)

	defer ctrl.Finish()

	h := Handler{
		HandleHelper: &fositeOAuth2.HandleHelper{
			AccessTokenStorage:  atStore,
			AccessTokenStrategy: chgen,
			Config: &fosite.Config{
				AccessTokenLifespan: time.Hour,
			},
		},
		Config:               &fosite.Config{},
		RefreshTokenStrategy: rtStrategy,
		RefreshTokenStorage:  rtStore,
	}
	for _, c := range []struct {
		name      string
		mock      func()
		req       *http.Request
		expectErr error
	}{
		{
			name:      "should fail because not responsible",
			expectErr: fosite.ErrUnknownRequest,
			mock: func() {
				areq.GrantTypes = fosite.Arguments{""}
			},
		},
		{
			name:      "should fail because grant_type not allowed",
			expectErr: fosite.ErrUnauthorizedClient,
			mock: func() {
				areq.GrantTypes = fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"}
				areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"authorization_code"}}
			},
		},
		{
			name: "should pass",
			mock: func() {
				areq.GrantTypes = fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"}
				areq.Session = &fosite.DefaultSession{}
				areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"}}
				chgen.EXPECT().GenerateAccessToken(gomock.Any(), areq).Return("tokenfoo.bar", "bar", nil)
				atStore.EXPECT().CreateAccessTokenSession(gomock.Any(), "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
			},
		},
		{
			name: "should populate both AT and RT",
			mock: func() {
				areq.GrantedScope = fosite.Arguments{"offline_access"}
				areq.GrantTypes = fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"}
				areq.Session = &fosite.DefaultSession{}
				areq.Client = &fosite.DefaultClient{
					GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
				}
				chgen.EXPECT().GenerateAccessToken(gomock.Any(), areq).Return("tokenfoo.bar", "bar", nil)
				atStore.EXPECT().CreateAccessTokenSession(gomock.Any(), "bar", gomock.Eq(areq.Sanitize([]string{}))).Return(nil)
				rtStrategy.EXPECT().GenerateRefreshToken(gomock.Any(), gomock.Any()).Return("refresh_token", "refresh_token_signature", nil)
				rtStore.EXPECT().CreateRefreshTokenSession(gomock.Any(), "refresh_token_signature", gomock.Eq(areq)).Return(nil)
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.mock()
			err := h.PopulateTokenEndpointResponse(context.TODO(), areq, aresp)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
