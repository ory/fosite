// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/storage"
)

type mockCodeStrategy struct {
	signature string
}

func (m *mockCodeStrategy) AuthorizeCodeSignature(ctx context.Context, token string) string {
	return m.signature
}

func (m *mockCodeStrategy) GenerateAuthorizeCode(ctx context.Context, requester fosite.Requester) (token string, signature string, err error) {
	return "", "", nil
}

func (m *mockCodeStrategy) ValidateAuthorizeCode(ctx context.Context, requester fosite.Requester, token string) (err error) {
	return nil
}

func TestPKCEHandleAuthorizeEndpointRequest(t *testing.T) {
	var config fosite.Config
	h := &Handler{
		Storage:               storage.NewMemoryStore(),
		AuthorizeCodeStrategy: new(oauth2.HMACSHAStrategy),
		Config:                &config,
	}
	w := fosite.NewAuthorizeResponse()
	r := fosite.NewAuthorizeRequest()
	c := &fosite.DefaultClient{}
	r.Client = c

	w.AddParameter("code", "foo")

	r.Form.Add("code_challenge", "challenge")
	r.Form.Add("code_challenge_method", "plain")

	r.ResponseTypes = fosite.Arguments{}
	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	r.ResponseTypes = fosite.Arguments{"code"}
	require.Error(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	r.ResponseTypes = fosite.Arguments{"code", "id_token"}
	require.Error(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	c.Public = true
	config.EnablePKCEPlainChallengeMethod = true
	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	c.Public = false
	config.EnablePKCEPlainChallengeMethod = true
	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	config.EnablePKCEPlainChallengeMethod = false
	require.Error(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	r.Form.Set("code_challenge_method", "S256")
	r.Form.Set("code_challenge", "")
	config.EnforcePKCE = true
	require.Error(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	r.Form.Set("code_challenge", "challenge")
	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))
}

func TestPKCEHandlerValidate(t *testing.T) {
	s := storage.NewMemoryStore()
	ms := &mockCodeStrategy{}
	config := &fosite.Config{}
	h := &Handler{Storage: s, AuthorizeCodeStrategy: ms, Config: config}
	pc := &fosite.DefaultClient{Public: true}

	s256verifier := "KGCt4m8AmjUvIR5ArTByrmehjtbxn1A49YpTZhsH8N7fhDr7LQayn9xx6mck"
	hash := sha256.New()
	hash.Write([]byte(s256verifier))
	s256challenge := base64.RawURLEncoding.EncodeToString(hash.Sum([]byte{}))

	for k, tc := range []struct {
		d           string
		grant       string
		force       bool
		enablePlain bool
		challenge   string
		method      string
		verifier    string
		code        string
		expectErr   error
		client      *fosite.DefaultClient
	}{
		{
			d:         "fails because not auth code flow",
			grant:     "not_authorization_code",
			expectErr: fosite.ErrUnknownRequest,
		},
		{
			d:           "passes with private client",
			grant:       "authorization_code",
			challenge:   "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			verifier:    "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			method:      "plain",
			client:      &fosite.DefaultClient{Public: false},
			enablePlain: true,
			force:       true,
			code:        "valid-code-1",
		},
		{
			d:         "fails because invalid code",
			grant:     "authorization_code",
			expectErr: fosite.ErrInvalidGrant,
			client:    pc,
			code:      "invalid-code-2",
		},
		{
			d:      "passes because auth code flow but pkce is not forced and no challenge given",
			grant:  "authorization_code",
			client: pc,
			code:   "valid-code-3",
		},
		{
			d:         "fails because auth code flow and pkce challenge given but plain is disabled",
			grant:     "authorization_code",
			challenge: "foo",
			client:    pc,
			expectErr: fosite.ErrInvalidRequest,
			code:      "valid-code-4",
		},
		{
			d:           "passes",
			grant:       "authorization_code",
			challenge:   "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			verifier:    "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			client:      pc,
			enablePlain: true,
			force:       true,
			code:        "valid-code-5",
		},
		{
			d:           "passes",
			grant:       "authorization_code",
			challenge:   "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			verifier:    "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			method:      "plain",
			client:      pc,
			enablePlain: true,
			force:       true,
			code:        "valid-code-6",
		},
		{
			d:           "fails because challenge and verifier do not match",
			grant:       "authorization_code",
			challenge:   "not-foo",
			verifier:    "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			method:      "plain",
			client:      pc,
			enablePlain: true,
			code:        "valid-code-7",
			expectErr:   fosite.ErrInvalidGrant,
		},
		{
			d:           "fails because challenge and verifier do not match",
			grant:       "authorization_code",
			challenge:   "not-foonot-foonot-foonot-foonot-foonot-foonot-foonot-foo",
			verifier:    "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			client:      pc,
			enablePlain: true,
			code:        "valid-code-8",
			expectErr:   fosite.ErrInvalidGrant,
		},
		{
			d:         "fails because verifier is too short",
			grant:     "authorization_code",
			challenge: "foo",
			verifier:  "foo",
			method:    "S256",
			client:    pc,
			force:     true,
			code:      "valid-code-9a",
			expectErr: fosite.ErrInvalidGrant,
		},
		{
			d:         "fails because verifier is too long",
			grant:     "authorization_code",
			challenge: "foo",
			verifier:  "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			method:    "S256",
			client:    pc,
			force:     true,
			code:      "valid-code-10",
			expectErr: fosite.ErrInvalidGrant,
		},
		{
			d:         "fails because verifier is malformed",
			grant:     "authorization_code",
			challenge: "foo",
			verifier:  `(!"/$%Z&$T()/)OUZI>$"&=/T(PUOI>"%/)TUOI&/(O/()RGTE>=/(%"/()="$/)(=()=/R/()=))`,
			method:    "S256",
			client:    pc,
			force:     true,
			code:      "valid-code-11",
			expectErr: fosite.ErrInvalidGrant,
		},
		{
			d:         "fails because challenge and verifier do not match",
			grant:     "authorization_code",
			challenge: "Zm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9v",
			verifier:  "Zm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9v",
			method:    "S256",
			client:    pc,
			force:     true,
			code:      "valid-code-12",
			expectErr: fosite.ErrInvalidGrant,
		},
		{
			d:         "passes because challenge and verifier match",
			grant:     "authorization_code",
			challenge: s256challenge,
			verifier:  s256verifier,
			method:    "S256",
			client:    pc,
			force:     true,
			code:      "valid-code-13",
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.d), func(t *testing.T) {
			config.EnablePKCEPlainChallengeMethod = tc.enablePlain
			config.EnforcePKCE = tc.force
			ms.signature = tc.code
			ar := fosite.NewAuthorizeRequest()
			ar.Form.Add("code_challenge", tc.challenge)
			ar.Form.Add("code_challenge_method", tc.method)
			require.NoError(t, s.CreatePKCERequestSession(context.Background(), fmt.Sprintf("valid-code-%d", k), ar))

			r := fosite.NewAccessRequest(nil)
			r.Client = tc.client
			r.GrantTypes = fosite.Arguments{tc.grant}
			r.Form.Add("code_verifier", tc.verifier)
			if tc.expectErr == nil {
				require.NoError(t, h.HandleTokenEndpointRequest(context.Background(), r))
			} else {
				err := h.HandleTokenEndpointRequest(context.Background(), r)
				require.EqualError(t, err, tc.expectErr.Error(), "%+v", err)
			}
		})
	}
}

func TestPKCEHandleTokenEndpointRequest(t *testing.T) {
	for k, tc := range []struct {
		d           string
		force       bool
		forcePublic bool
		enablePlain bool
		challenge   string
		method      string
		expectErr   bool
		client      *fosite.DefaultClient
	}{
		{
			d: "should pass because pkce is not enforced",
		},
		{
			d:         "should fail because plain is not enabled and method is empty which defaults to plain",
			expectErr: true,
			force:     true,
		},
		{
			d:           "should fail because force is enabled and no challenge was given",
			force:       true,
			enablePlain: true,
			expectErr:   true,
			method:      "S256",
		},
		{
			d:           "should fail because forcePublic is enabled, the client is public, and no challenge was given",
			forcePublic: true,
			client:      &fosite.DefaultClient{Public: true},
			expectErr:   true,
			method:      "S256",
		},
		{
			d:         "should fail because although force is enabled and a challenge was given, plain is disabled",
			force:     true,
			expectErr: true,
			method:    "plain",
			challenge: "challenge",
		},
		{
			d:         "should fail because although force is enabled and a challenge was given, plain is disabled and method is empty",
			force:     true,
			expectErr: true,
			challenge: "challenge",
		},
		{
			d:         "should fail because invalid challenge method",
			force:     true,
			expectErr: true,
			method:    "invalid",
			challenge: "challenge",
		},
		{
			d:         "should pass because force is enabled with challenge given and method is S256",
			force:     true,
			method:    "S256",
			challenge: "challenge",
		},
		{
			d:           "should pass because forcePublic is enabled with challenge given and method is S256",
			forcePublic: true,
			client:      &fosite.DefaultClient{Public: true},
			method:      "S256",
			challenge:   "challenge",
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.d), func(t *testing.T) {
			h := &Handler{
				Config: &fosite.Config{
					EnforcePKCE:                    tc.force,
					EnforcePKCEForPublicClients:    tc.forcePublic,
					EnablePKCEPlainChallengeMethod: tc.enablePlain,
				},
			}

			if tc.expectErr {
				assert.Error(t, h.validate(context.Background(), tc.challenge, tc.method, tc.client))
			} else {
				assert.NoError(t, h.validate(context.Background(), tc.challenge, tc.method, tc.client))
			}
		})
	}
}
