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

type mockDeviceCodeStrategy struct {
	signature string
}

func (m *mockDeviceCodeStrategy) DeviceCodeSignature(ctx context.Context, token string) string {
	return m.signature
}

func (m *mockDeviceCodeStrategy) GenerateDeviceCode(ctx context.Context) (token string, signature string, err error) {
	return "", "", nil
}

func (m *mockDeviceCodeStrategy) ValidateDeviceCode(ctx context.Context, requester fosite.Requester, token string) (err error) {
	return nil
}

type mockUserCodeStrategy struct {
	signature string
}

func (m *mockUserCodeStrategy) UserCodeSignature(ctx context.Context, token string) string {
	return m.signature
}

func (m *mockUserCodeStrategy) GenerateUserCode(ctx context.Context) (token string, signature string, err error) {
	return "", "", nil
}

func (m *mockUserCodeStrategy) ValidateUserCode(ctx context.Context, requester fosite.Requester, token string) (err error) {
	return nil
}

func TestPKCEHandlerDevice_HandleDeviceAuthorizeEndpointRequest(t *testing.T) {
	var config fosite.Config
	h := &HandlerDevice{
		Storage:            storage.NewMemoryStore(),
		DeviceCodeStrategy: new(oauth2.HMACSHAStrategy),
		UserCodeStrategy:   new(oauth2.HMACSHAStrategy),
		Config:             &config,
	}
	w := fosite.NewDeviceResponse()
	r := fosite.NewDeviceRequest()
	config.GlobalSecret = []byte("thisissecret")

	w.SetDeviceCode("foo")

	r.Form.Add("code_challenge", "challenge")
	r.Form.Add("code_challenge_method", "plain")

	c := &fosite.DefaultClient{}
	r.Client = c
	require.NoError(t, h.HandleDeviceEndpointRequest(context.Background(), r, w))

	c = &fosite.DefaultClient{
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
	}
	r.Client = c
	require.Error(t, h.HandleDeviceEndpointRequest(context.Background(), r, w))

	c.Public = true
	config.EnablePKCEPlainChallengeMethod = true
	require.NoError(t, h.HandleDeviceEndpointRequest(context.Background(), r, w))

	c.Public = false
	config.EnablePKCEPlainChallengeMethod = true
	require.NoError(t, h.HandleDeviceEndpointRequest(context.Background(), r, w))

	config.EnablePKCEPlainChallengeMethod = false
	require.Error(t, h.HandleDeviceEndpointRequest(context.Background(), r, w))

	r.Form.Set("code_challenge_method", "S256")
	r.Form.Set("code_challenge", "")
	config.EnforcePKCE = true
	require.Error(t, h.HandleDeviceEndpointRequest(context.Background(), r, w))

	r.Form.Set("code_challenge", "challenge")
	require.NoError(t, h.HandleDeviceEndpointRequest(context.Background(), r, w))
}

func TestPKCEHandlerDevice_HandlerDeviceValidate(t *testing.T) {
	s := storage.NewMemoryStore()
	ds := &mockDeviceCodeStrategy{}
	us := &mockUserCodeStrategy{}
	config := &fosite.Config{}
	h := &HandlerDevice{
		Storage:            s,
		UserCodeStrategy:   us,
		DeviceCodeStrategy: ds,
		Config:             config,
	}
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
			grant:     "not_urn:ietf:params:oauth:grant-type:device_code",
			expectErr: fosite.ErrUnknownRequest,
		},
		{
			d:           "passes with private client",
			grant:       "urn:ietf:params:oauth:grant-type:device_code",
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
			grant:     "urn:ietf:params:oauth:grant-type:device_code",
			expectErr: fosite.ErrInvalidGrant,
			client:    pc,
			code:      "invalid-code-2",
		},
		{
			d:      "passes because auth code flow but pkce is not forced and no challenge given",
			grant:  "urn:ietf:params:oauth:grant-type:device_code",
			client: pc,
			code:   "valid-code-3",
		},
		{
			d:         "fails because auth code flow and pkce challenge given but plain is disabled",
			grant:     "urn:ietf:params:oauth:grant-type:device_code",
			challenge: "foo",
			client:    pc,
			expectErr: fosite.ErrInvalidRequest,
			code:      "valid-code-4",
		},
		{
			d:           "passes",
			grant:       "urn:ietf:params:oauth:grant-type:device_code",
			challenge:   "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			verifier:    "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			client:      pc,
			enablePlain: true,
			force:       true,
			code:        "valid-code-5",
		},
		{
			d:           "passes",
			grant:       "urn:ietf:params:oauth:grant-type:device_code",
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
			grant:       "urn:ietf:params:oauth:grant-type:device_code",
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
			grant:       "urn:ietf:params:oauth:grant-type:device_code",
			challenge:   "not-foonot-foonot-foonot-foonot-foonot-foonot-foonot-foo",
			verifier:    "foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo",
			client:      pc,
			enablePlain: true,
			code:        "valid-code-8",
			expectErr:   fosite.ErrInvalidGrant,
		},
		{
			d:         "fails because verifier is too short",
			grant:     "urn:ietf:params:oauth:grant-type:device_code",
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
			grant:     "urn:ietf:params:oauth:grant-type:device_code",
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
			grant:     "urn:ietf:params:oauth:grant-type:device_code",
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
			grant:     "urn:ietf:params:oauth:grant-type:device_code",
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
			grant:     "urn:ietf:params:oauth:grant-type:device_code",
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
			ds.signature = tc.code
			ar := fosite.NewAuthorizeRequest()
			ar.Form.Add("code_challenge", tc.challenge)
			ar.Form.Add("code_challenge_method", tc.method)
			require.NoError(t, s.CreatePKCERequestSession(nil, fmt.Sprintf("valid-code-%d", k), ar))

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

func TestPKCEHandlerDevice_HandleTokenEndpointRequest(t *testing.T) {
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
			h := &HandlerDevice{
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
