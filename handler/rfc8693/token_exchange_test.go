// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"

	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/hmac"
	"github.com/ory/fosite/token/jwt"
	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/rfc8693"
	. "github.com/ory/fosite/handler/rfc8693"
)

func TestAccessTokenExchangeImpersonation(t *testing.T) {
	store := storage.NewExampleStore()
	jwks := getJWKS()
	customJWTType := &JWTType{
		Name: "urn:custom:jwt",
		JWTValidationConfig: JWTValidationConfig{
			ValidateJTI: true,
			ValidateFunc: jwt.Keyfunc(func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Header["kid"].(string); !ok {
					return nil, errors.New("invalid kid")
				}
				if _, ok := t.Claims["iss"].(string); !ok {
					return nil, errors.New("invalid iss")
				}

				return findPublicKey(t, jwks, true)
			}),
			JWTLifetimeToleranceWindow: 15 * time.Minute,
		},
		JWTIssueConfig: JWTIssueConfig{
			Audience: []string{"https://resource1.com"},
		},
		Issuer: "https://customory.com",
	}

	config := &fosite.Config{
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		GlobalSecret:             []byte("some-secret-thats-random-some-secret-thats-random-"),
		RFC8693TokenTypes: map[string]fosite.RFC8693TokenType{
			AccessTokenType: &DefaultTokenType{
				Name: AccessTokenType,
			},
			IDTokenType: &DefaultTokenType{
				Name: IDTokenType,
			},
			RefreshTokenType: &DefaultTokenType{
				Name: RefreshTokenType,
			},
			customJWTType.GetName(nil): customJWTType,
		},
		DefaultRequestedTokenType: AccessTokenType,
	}

	coreStrategy := &oauth2.HMACSHAStrategy{
		Enigma: &hmac.HMACStrategy{Config: config},
		Config: config,
	}

	genericTEHandler := &TokenExchangeGrantHandler{
		Config:                   config,
		ScopeStrategy:            config.ScopeStrategy,
		AudienceMatchingStrategy: config.AudienceMatchingStrategy,
	}

	accessTokenHandler := &AccessTokenTypeHandler{
		Config:               config,
		AccessTokenLifespan:  5 * time.Minute,
		RefreshTokenLifespan: 5 * time.Minute,
		RefreshTokenScopes:   []string{"offline"},
		CoreStrategy:         coreStrategy,
		ScopeStrategy:        config.ScopeStrategy,
		Storage:              store,
	}

	for _, c := range []struct {
		handlers    []fosite.TokenEndpointHandler
		areq        *fosite.AccessRequest
		description string
		expectErr   error
		expect      func(t *testing.T, areq *fosite.AccessRequest, aresp *fosite.AccessResponse)
	}{
		{
			handlers: []fosite.TokenEndpointHandler{genericTEHandler, accessTokenHandler},
			areq: &fosite.AccessRequest{
				Request: fosite.Request{
					ID:     uuid.New(),
					Client: store.Clients["my-client"],
					Form: url.Values{
						"subject_token_type": []string{rfc8693.AccessTokenType},
						"subject_token": []string{createAccessToken(context.Background(), coreStrategy, store,
							store.Clients["custom-lifespan-client"])},
					},
					Session: &rfc8693.DefaultSession{
						DefaultSession: &openid.DefaultSession{},
						Extra:          map[string]interface{}{},
					},
				},
			},
			description: "should pass because a valid access token is exchanged for another access token",
			expect: func(t *testing.T, areq *fosite.AccessRequest, aresp *fosite.AccessResponse) {
				assert.NotEmpty(t, aresp.AccessToken, "Access token is empty; %+v", aresp)
			},
		},
	} {
		t.Run("case="+c.description, func(t *testing.T) {
			ctx := context.Background()
			aresp := fosite.NewAccessResponse()
			found := false
			var err error
			c.areq.Form.Set("grant_type", string(fosite.GrantTypeTokenExchange))
			c.areq.GrantTypes = fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"}
			c.areq.Client = store.Clients["my-client"]
			for _, loader := range c.handlers {
				// Is the loader responsible for handling the request?
				if !loader.CanHandleTokenEndpointRequest(ctx, c.areq) {
					continue
				}

				// The handler **is** responsible!
				found = true

				if err = loader.HandleTokenEndpointRequest(ctx, c.areq); err == nil {
					continue
				} else if errors.Is(err, fosite.ErrUnknownRequest) {
					// This is a duplicate because it should already have been handled by
					// `loader.CanHandleTokenEndpointRequest(accessRequest)` but let's keep it for sanity.
					//
					err = nil
					continue
				} else if err != nil {
					break
				}
			}

			if !found {
				assert.Fail(t, "Unable to find a valid handler")
			}

			// now execute the response
			if err == nil {
				for _, loader := range c.handlers {
					// Is the loader responsible for handling the request?
					if !loader.CanHandleTokenEndpointRequest(ctx, c.areq) {
						continue
					}

					// The handler **is** responsible!

					if err = loader.PopulateTokenEndpointResponse(ctx, c.areq, aresp); err == nil {
						found = true
					} else if errors.Is(err, fosite.ErrUnknownRequest) {
						// This is a duplicate because it should already have been handled by
						// `loader.CanHandleTokenEndpointRequest(accessRequest)` but let's keep it for sanity.
						//
						err = nil
						continue
					} else if err != nil {
						break
					}
				}
			}

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}

			if c.expect != nil {
				c.expect(t, c.areq, aresp)
			}
		})
	}
}

func findPublicKey(t *jwt.Token, set *jose.JSONWebKeySet, expectsRSAKey bool) (interface{}, error) {
	keys := set.Keys
	if len(keys) == 0 {
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("The retrieved JSON Web Key Set does not contain any key."))
	}

	kid, ok := t.Header["kid"].(string)
	if ok {
		keys = set.Key(kid)
	}

	if len(keys) == 0 {
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("The JSON Web Token uses signing key with kid '%s', which could not be found.", kid))
	}

	for _, key := range keys {
		if key.Use != "sig" {
			continue
		}
		if expectsRSAKey {
			if k, ok := key.Key.(*rsa.PublicKey); ok {
				return k, nil
			}
		} else {
			if k, ok := key.Key.(*ecdsa.PublicKey); ok {
				return k, nil
			}
		}
	}

	if expectsRSAKey {
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("Unable to find RSA public key with use='sig' for kid '%s' in JSON Web Key Set.", kid))
	} else {
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("Unable to find ECDSA public key with use='sig' for kid '%s' in JSON Web Key Set.", kid))
	}
}

func getJWKS() *jose.JSONWebKeySet {
	jwks := &jose.JSONWebKeySet{}
	jwksStr := `{"keys":[
		{
			"kty": "RSA",
			"e": "AQAB",
			"kid": "demojwtsigner",
			"use": "sig",
			"n": "nyEEwueLcSFRUSPdy9AL5Vf6X7QDuL8mFMOR2liM1LeluSHCSYIoN-h6xxMkwDfr6626EOhJVxMxeBuLaG-_3QWWjvicUdIpevj73U1jqQT7MaMPI3ms7rm0v1OHfabyLbrCjDniL_8Ym15H_RwVqF31kXIcKVqMtJWRWkeoOrSSqUq4h28rRDUi8HXUTAvSoQYnZ-J-sICME7G-ZYVJtIQObT6AjMuM_y54vCH8ViVE9aOQ2rV3Wi-TKEgiV9Ik1KB6EdzCB4CYK2HYy_OgheF0ggeWuwHOegBpVR4BqlQyZJKJyhKhWZhfYHmWkm_V-7KZtrWHoVQ_NhOAcT18qw"
		},
		{
			"kty": "RSA",
			"e": "AQAB",
			"use": "sig",
			"kid": "cibarsa",
			"n": "mP6Zt6qN3YEE4asCoMmvVEJcXTv00I1AamJvmkUx0Ax9-w_AcBa7zeEgysEK0CQG2jXLGaRQ-W0D74Z5K_aAnx7dbRSmArxe-dlGm08_KoOwErh2dHq5_GezYURTWddv_2hjObJcoxQtzKmQQCbcLH_8_AGdVO6KZYfPElPqsEW1VEdiFkOgL3LPw2KRVPB3g6yj3t2Ot9edB8AnKwyD8eFDpV48Q-w9DfgqY_XlOYTDgtpBDGADP_XScL5Le7wZRfZp1N4qRYeak2NjKMDUpxPt0tX5d-GHjTG6ph9J-hzBFnSbUUpQEHol7fAVy6GFOwVbY9-yJkoV7CebstDryQ"
		},
		{
			"kty": "EC",
			"use": "sig",
			"crv": "P-521",
			"kid": "cibaec521",
			"x": "AVnfaEpeCrVt8mozqVaJ37hW7JBhHVu9q8BK0w6-wTAhJ8FBoWFxOPGT-Kc0-h0weNTh1UMGEoXmXFArN6qGp1yz",
			"y": "AN6HK2bqfD2Y_3r6_WZa5Z6IyZao8Aw9OZBJ0IMrbnmay6z0-Oghqd7NChR6BORkizLetSe-4HbOxllPSztHFP2d"
		}
	]}`

	if err := json.Unmarshal([]byte(jwksStr), jwks); err != nil {
		panic(err.Error())
	}

	return jwks
}

func createAccessToken(ctx context.Context, coreStrategy oauth2.CoreStrategy, storage oauth2.AccessTokenStorage, client fosite.Client) string {
	request := &fosite.AccessRequest{
		GrantTypes: fosite.Arguments{"password"},
		Request: fosite.Request{
			Session: &fosite.DefaultSession{
				Username: "peter",
				Subject:  "peter",
				ExpiresAt: map[fosite.TokenType]time.Time{
					fosite.AccessToken: time.Now().UTC().Add(10 * time.Minute),
				},
			},
			Client: client,
		},
	}

	token, signature, err := coreStrategy.GenerateAccessToken(ctx, request)
	if err != nil {
		panic(err.Error())
	} else if err := storage.CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})); err != nil {
		panic(err.Error())
	}

	return token
}
