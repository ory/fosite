package pkce

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCodeStrategy struct {
	signature string
}

func (m *mockCodeStrategy) AuthorizeCodeSignature(token string) string {
	return m.signature
}

func (m *mockCodeStrategy) GenerateAuthorizeCode(ctx context.Context, requester fosite.Requester) (token string, signature string, err error) {
	return "", "", nil
}

func (m *mockCodeStrategy) ValidateAuthorizeCode(ctx context.Context, requester fosite.Requester, token string) (err error) {
	return nil
}

func TestPKCEHandleAuthorizeEndpointRequest(t *testing.T) {
	h := &Handler{}
	w := fosite.NewAuthorizeResponse()
	r := fosite.NewAuthorizeRequest()
	c := &fosite.DefaultClient{}
	r.Client = c

	r.Form.Add("code_challenge", "challenge")
	r.Form.Add("code_challenge_method", "plain")

	r.ResponseTypes = fosite.Arguments{}
	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	r.ResponseTypes = fosite.Arguments{"code"}
	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	c.Public = true
	h.EnablePlainChallengeMethod = true
	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	h.EnablePlainChallengeMethod = false
	require.Error(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	r.Form.Set("code_challenge_method", "S256")
	r.Form.Set("code_challenge", "")
	h.Force = true
	require.Error(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))

	r.Form.Set("code_challenge", "challenge")
	require.NoError(t, h.HandleAuthorizeEndpointRequest(context.Background(), r, w))
}

func TestPKCEHandlerValidate(t *testing.T) {
	s := storage.NewMemoryStore()
	ms := &mockCodeStrategy{}
	h := &Handler{
		CoreStorage: s, AuthorizeCodeStrategy: ms,
	}
	pc := &fosite.DefaultClient{Public: true}

	s256verifier := "11111111111111111111111111111111111111111111111111111111111111111111"
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
			d:         "fails because not auth code flow",
			grant:     "not_authorization_code",
			expectErr: fosite.ErrUnknownRequest,
			client:    &fosite.DefaultClient{Public: false},
		},
		{
			d:         "fails because invalid code",
			grant:     "authorization_code",
			expectErr: fosite.ErrServerError,
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
			challenge:   "foo",
			verifier:    "foo",
			client:      pc,
			enablePlain: true,
			force:       true,
			code:        "valid-code-5",
		},
		{
			d:           "passes",
			grant:       "authorization_code",
			challenge:   "foo",
			verifier:    "foo",
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
			verifier:    "foo",
			method:      "plain",
			client:      pc,
			enablePlain: true,
			code:        "valid-code-7",
			expectErr:   fosite.ErrInvalidGrant,
		},
		{
			d:           "fails because challenge and verifier do not match",
			grant:       "authorization_code",
			challenge:   "not-foo",
			verifier:    "foo",
			client:      pc,
			enablePlain: true,
			code:        "valid-code-8",
			expectErr:   fosite.ErrInvalidGrant,
		},
		{
			d:         "fails because verifier has low entropy",
			grant:     "authorization_code",
			challenge: "foo",
			verifier:  "foo",
			method:    "S256",
			client:    pc,
			force:     true,
			code:      "valid-code-9",
			expectErr: fosite.ErrInsufficientEntropy,
		},
		{
			d:         "fails because challenge and verifier do not match",
			grant:     "authorization_code",
			challenge: "Zm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9v",
			verifier:  "Zm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9vZm9v",
			method:    "S256",
			client:    pc,
			force:     true,
			code:      "valid-code-10",
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
			code:      "valid-code-11",
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.d), func(t *testing.T) {
			h.EnablePlainChallengeMethod = tc.enablePlain
			h.Force = tc.force
			ms.signature = tc.code
			ar := fosite.NewAuthorizeRequest()
			ar.Form.Add("code_challenge", tc.challenge)
			ar.Form.Add("code_challenge_method", tc.method)
			require.NoError(t, s.CreateAuthorizeCodeSession(nil, fmt.Sprintf("valid-code-%d", k), ar))

			r := fosite.NewAccessRequest(nil)
			r.Client = tc.client
			r.GrantTypes = fosite.Arguments{tc.grant}
			r.Form.Add("code_verifier", tc.verifier)
			if tc.expectErr == nil {
				require.NoError(t, h.HandleTokenEndpointRequest(context.Background(), r))
			} else {
				require.EqualError(t, h.HandleTokenEndpointRequest(context.Background(), r), tc.expectErr.Error())
			}
		})
	}
}

func TestPKCEHandleTokenEndpointRequest(t *testing.T) {
	for k, tc := range []struct {
		d           string
		force       bool
		enablePlain bool
		challenge   string
		method      string
		expectErr   bool
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
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.d), func(t *testing.T) {
			h := &Handler{
				Force: tc.force,
				EnablePlainChallengeMethod: tc.enablePlain,
			}

			if tc.expectErr {
				assert.Error(t, h.validate(tc.challenge, tc.method))
			} else {
				assert.NoError(t, h.validate(tc.challenge, tc.method))
			}
		})
	}
}
