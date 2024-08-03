// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/internal/gen"
	"github.com/ory/fosite/token/jwt"
)

func TestJWTStrategy_GenerateIDToken(t *testing.T) {
	var j = &DefaultStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(_ context.Context) (interface{}, error) {
				return key, nil
			}},
		Config: &fosite.Config{
			MinParameterEntropy: fosite.MinParameterEntropy,
		},
	}

	var req *fosite.AccessRequest
	for k, c := range []struct {
		description string
		setup       func()
		expectErr   bool
	}{
		{
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("nonce", "some-secure-nonce-state")
			},
			expectErr: false,
		},
		{
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().UTC(),
						RequestedAt: time.Now().UTC(),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("nonce", "some-secure-nonce-state")
				req.Form.Set("max_age", "1234")
			},
			expectErr: false,
		},
		{
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:   "peter",
						ExpiresAt: time.Now().UTC().Add(-time.Hour),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("nonce", "some-secure-nonce-state")
			},
			expectErr: true,
		},
		{
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("nonce", "some-secure-nonce-state")
				req.Form.Set("max_age", "1234")
			},
			expectErr: true,
		},
		{
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims:  &jwt.IDTokenClaims{},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("nonce", "some-secure-nonce-state")
			},
			expectErr: true,
		},
		{
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
				})
			},
			expectErr: false,
		},
		{
			description: "should pass because max_age was requested and auth_time happened after initial request time",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().UTC(),
						RequestedAt: time.Now().UTC(),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("max_age", "60")
			},
			expectErr: false,
		},
		{
			description: "should fail because max_age was requested and auth_time has expired",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:  "peter",
						AuthTime: time.Now().Add(-time.Hour).UTC(),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("max_age", "60")
			},
			expectErr: true,
		},
		{
			description: "should fail because prompt=none was requested and auth_time indicates fresh login",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().UTC(),
						RequestedAt: time.Now().Add(-time.Minute),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("prompt", "none")
			},
			expectErr: true,
		},
		{
			description: "should pass because prompt=none was requested and auth_time indicates fresh login but grant type is refresh_token",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().UTC(),
						RequestedAt: time.Now().Add(-time.Minute),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("prompt", "none")
				req.Form.Set("grant_type", "refresh_token")
			},
			expectErr: false,
		},
		{
			description: "should pass because prompt=none was requested and auth_time indicates old login",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().Add(-time.Hour).UTC(),
						RequestedAt: time.Now().Add(-time.Minute),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("prompt", "none")
			},
			expectErr: false,
		},
		{
			description: "should pass because prompt=login was requested and auth_time indicates fresh login",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().UTC(),
						RequestedAt: time.Now().Add(-time.Minute),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("prompt", "login")
			},
			expectErr: false,
		},
		{
			description: "should fail because prompt=login was requested and auth_time indicates old login",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().Add(-time.Hour).UTC(),
						RequestedAt: time.Now().Add(-time.Minute),
					},
					Headers: &jwt.Headers{},
				})
				req.Form.Set("prompt", "login")
			},
			expectErr: true,
		},
		{
			description: "should pass because id_token_hint subject matches subject from claims",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().Add(-time.Hour).UTC(),
						RequestedAt: time.Now().Add(-time.Minute),
					},
					Headers: &jwt.Headers{},
				})
				token, _ := j.GenerateIDToken(context.TODO(), time.Duration(0), fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject: "peter",
					},
					Headers: &jwt.Headers{},
				}))
				req.Form.Set("id_token_hint", token)
			},
			expectErr: false,
		},
		{
			description: "should pass even though token is expired",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().Add(-time.Hour).UTC(),
						RequestedAt: time.Now().Add(-time.Minute),
					},
					Headers: &jwt.Headers{},
				})
				token, _ := j.GenerateIDToken(context.TODO(), time.Duration(0), fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:   "peter",
						ExpiresAt: time.Now().Add(-time.Hour).UTC(),
					},
					Headers: &jwt.Headers{},
				}))
				req.Form.Set("id_token_hint", token)
			},
			expectErr: false,
		},
		{
			description: "should fail because id_token_hint subject does not match subject from claims",
			setup: func() {
				req = fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{
						Subject:     "peter",
						AuthTime:    time.Now().Add(-time.Hour).UTC(),
						RequestedAt: time.Now().Add(-time.Minute),
					},
					Headers: &jwt.Headers{},
				})
				token, _ := j.GenerateIDToken(context.TODO(), time.Duration(0), fosite.NewAccessRequest(&DefaultSession{
					Claims: &jwt.IDTokenClaims{Subject: "alice"}, Headers: &jwt.Headers{},
				}))
				req.Form.Set("id_token_hint", token)
			},
			expectErr: true,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.setup()
			token, err := j.GenerateIDToken(context.TODO(), time.Duration(0), req)
			assert.Equal(t, c.expectErr, err != nil, "%d: %+v", k, err)
			if !c.expectErr {
				assert.NotEmpty(t, token)
			}
		})
	}
}

func TestJWTStrategy_DecodeIDToken(t *testing.T) {
	var j = &DefaultStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(_ context.Context) (interface{}, error) {
				return key, nil
			}},
		Config: &fosite.Config{
			MinParameterEntropy: fosite.MinParameterEntropy,
		},
	}

	var anotherKey = gen.MustRSAKey()

	var genIDToken = func(c jwt.IDTokenClaims) string {
		s, _, err := j.Generate(context.TODO(), c.ToMapClaims(), jwt.NewHeaders())
		require.NoError(t, err)
		return s
	}

	var token string
	var decoder *DefaultStrategy
	for k, c := range []struct {
		description string
		setup       func()
		expectErr   bool
	}{
		{
			description: "should pass with valid token",
			setup: func() {
				token = genIDToken(jwt.IDTokenClaims{
					Subject:     "peter",
					RequestedAt: time.Now(),
					ExpiresAt:   time.Now().Add(time.Hour),
				})
				decoder = j
			},
			expectErr: false,
		},
		{
			description: "should pass even though token is expired",
			setup: func() {
				token = genIDToken(jwt.IDTokenClaims{
					Subject:     "peter",
					RequestedAt: time.Now(),
					ExpiresAt:   time.Now().Add(-time.Hour),
				})
				decoder = j
			},
			expectErr: false,
		},
		{
			description: "should fail because token is decoded with wrong key",
			setup: func() {
				token = genIDToken(jwt.IDTokenClaims{
					Subject:     "peter",
					RequestedAt: time.Now(),
					ExpiresAt:   time.Now().Add(time.Hour),
				})
				decoder = &DefaultStrategy{
					Signer: &jwt.DefaultSigner{
						GetPrivateKey: func(_ context.Context) (interface{}, error) {
							return anotherKey, nil
						}},
					Config: &fosite.Config{
						MinParameterEntropy: fosite.MinParameterEntropy,
					},
				}
			},
			expectErr: true,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, c.description), func(t *testing.T) {
			c.setup()
			req := fosite.NewAccessRequest(&DefaultSession{})
			idtoken, err := decoder.DecodeIDToken(context.Background(), req, token)
			assert.Equal(t, c.expectErr, err != nil, "%d: %+v", k, err)
			if !c.expectErr {
				assert.NotNil(t, idtoken)
			}
		})
	}
}
