// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite/internal/gen"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/hmac"
	"github.com/ory/fosite/token/jwt"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/rfc8693"
	. "github.com/ory/fosite/handler/rfc8693"
)

// expose key to verify id_token
var key = gen.MustRSAKey()

func TestAccessTokenExchangeImpersonation(t *testing.T) {
	store := storage.NewExampleStore()
	jwtName := "urn:custom:jwt"

	jwtSigner := &jwt.DefaultSigner{
		GetPrivateKey: func(_ context.Context) (interface{}, error) {
			return key, nil
		},
	}

	customJWTType := &JWTType{
		Name: jwtName,
		JWTValidationConfig: JWTValidationConfig{
			ValidateJTI: true,
			ValidateFunc: jwt.Keyfunc(func(t *jwt.Token) (interface{}, error) {
				return key.PublicKey, nil
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

	customJWTHandler := &CustomJWTTypeHandler{
		Config: config,
		JWTStrategy: &jwt.DefaultSigner{
			GetPrivateKey: func(_ context.Context) (interface{}, error) {
				return key, nil
			},
		},
		Storage: store,
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
				req, err := introspectAccessToken(context.Background(), aresp.AccessToken, coreStrategy, store)
				require.NoError(t, err, "Error occurred during introspection; err=%v", err)

				assert.EqualValues(t, "peter", req.GetSession().GetSubject(), "Subject did not match the expected value")
			},
		},
		{
			handlers: []fosite.TokenEndpointHandler{genericTEHandler, accessTokenHandler, customJWTHandler},
			areq: &fosite.AccessRequest{
				Request: fosite.Request{
					ID:     uuid.New(),
					Client: store.Clients["my-client"],
					Form: url.Values{
						"subject_token_type": []string{jwtName},
						"subject_token": []string{createJWT(context.Background(), jwtSigner, jwt.MapClaims{
							"subject": "peter_for_jwt",
							"jti":     uuid.New(),
							"iss":     "https://customory.com",
							"sub":     "peter",
							"exp":     time.Now().Add(15 * time.Minute).Unix(),
						})},
					},
					Session: &rfc8693.DefaultSession{
						DefaultSession: &openid.DefaultSession{},
						Extra:          map[string]interface{}{},
					},
				},
			},
			description: "should pass because a valid custom JWT is exchanged for access token",
			expect: func(t *testing.T, areq *fosite.AccessRequest, aresp *fosite.AccessResponse) {
				assert.NotEmpty(t, aresp.AccessToken, "Access token is empty; %+v", aresp)
				req, err := introspectAccessToken(context.Background(), aresp.AccessToken, coreStrategy, store)
				require.NoError(t, err, "Error occurred during introspection; err=%v", err)

				assert.EqualValues(t, "peter_for_jwt", req.GetSession().GetSubject(), "Subject did not match the expected value")
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

			var rfcerr *fosite.RFC6749Error
			rfcerr, _ = err.(*fosite.RFC6749Error)
			if rfcerr == nil {
				rfcerr = fosite.ErrServerError
			}
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error(), "Error received: %v, rfcerr=%s", err, rfcerr.GetDescription())
			} else {
				require.NoError(t, err, "Error received: %v, rfcerr=%s", err, rfcerr.GetDescription())
			}

			if c.expect != nil {
				c.expect(t, c.areq, aresp)
			}
		})
	}
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

func createJWT(ctx context.Context, signer jwt.Signer, claims jwt.MapClaims) string {
	token, _, err := signer.Generate(ctx, claims, &jwt.Headers{})
	if err != nil {
		panic(err.Error())
	}

	return token
}

func introspectAccessToken(ctx context.Context, token string, coreStrategy oauth2.CoreStrategy, storage oauth2.CoreStorage) (
	fosite.Requester, error) {
	sig := coreStrategy.AccessTokenSignature(ctx, token)
	or, err := storage.GetAccessTokenSession(ctx, sig, &fosite.DefaultSession{})
	return or, err
}
