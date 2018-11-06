/*
 * Copyright © 2017-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
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
 * @Copyright 	2017-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package fosite_test

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	jose "gopkg.in/square/go-jose.v2"

	. "github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/storage"
)

func mustGenerateAssertion(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey, kid string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)
	return tokenString
}

func mustGenerateHSAssertion(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey, kid string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("aaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccddddddddddddddddddddddd"))
	require.NoError(t, err)
	return tokenString
}

func mustGenerateNoneAssertion(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey, kid string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return tokenString
}

func TestAuthenticateClient(t *testing.T) {
	const at = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	hasher := &BCrypt{WorkFactor: 6}
	f := &Fosite{
		JWKSFetcherStrategy: NewDefaultJWKSFetcherStrategy(),
		Store:               storage.NewMemoryStore(),
		Hasher:              hasher,
		TokenURL:            "token-url",
	}

	barSecret, err := hasher.Hash(context.TODO(), []byte("bar"))
	require.NoError(t, err)

	key := internal.MustRSAKey()
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID: "kid-foo",
				Use:   "sig",
				Key:   &key.PublicKey,
			},
		},
	}

	var h http.HandlerFunc
	h = func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(jwks))
	}
	ts := httptest.NewServer(h)
	defer ts.Close()

	for k, tc := range []struct {
		d             string
		client        *DefaultOpenIDConnectClient
		assertionType string
		assertion     string
		r             *http.Request
		form          url.Values
		expectErr     error
	}{
		{
			d:         "should fail because authentication can not be determined",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo"}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:      url.Values{},
			r:         new(http.Request),
			expectErr: ErrInvalidRequest,
		},
		{
			d:         "should fail because client does not exist",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Public: true}, TokenEndpointAuthMethod: "none"},
			form:      url.Values{"client_id": []string{"bar"}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should pass because client is public and authentication requirements are met",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Public: true}, TokenEndpointAuthMethod: "none"},
			form:   url.Values{"client_id": []string{"foo"}},
			r:      new(http.Request),
		},
		{
			d:         "should fail because auth method is not none",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Public: true}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:      url.Values{"client_id": []string{"foo"}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should pass because client is confidential and id and secret match in post body",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_post"},
			form:   url.Values{"client_id": []string{"foo"}, "client_secret": []string{"bar"}},
			r:      new(http.Request),
		},
		{
			d:         "should fail because client is confidential and secret does not match in post body",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_post"},
			form:      url.Values{"client_id": []string{"foo"}, "client_secret": []string{"baz"}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:         "should fail because client is confidential and id does not exist in post body",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_post"},
			form:      url.Values{"client_id": []string{"foo"}, "client_secret": []string{"bar"}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should pass because client is confidential and id and secret match in header",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:   url.Values{},
			r:      &http.Request{Header: http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("foo:bar"))}}},
		},
		{
			d:         "should fail because auth method is not client_secret_basic",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_post"},
			form:      url.Values{},
			r:         &http.Request{Header: http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("foo:bar"))}}},
			expectErr: ErrInvalidClient,
		},
		{
			d:         "should fail because client is confidential and secret does not match in header",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:      url.Values{},
			r:         &http.Request{Header: http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("foo:baz"))}}},
			expectErr: ErrInvalidClient,
		},
		{
			d:         "should fail because client id is not encoded using application/x-www-form-urlencoded",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:      url.Values{},
			r:         &http.Request{Header: http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("%%%%%%:foo"))}}},
			expectErr: ErrInvalidRequest,
		},
		{
			d:         "should fail because client secret is not encoded using application/x-www-form-urlencoded",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:      url.Values{},
			r:         &http.Request{Header: http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("foo:%%%%%%%"))}}},
			expectErr: ErrInvalidRequest,
		},
		{
			d:         "should fail because client is confidential and id does not exist in header",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:      url.Values{},
			r:         &http.Request{Header: http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("foo:bar"))}}},
			expectErr: ErrInvalidClient,
		},
		{
			d:         "should fail because client_assertion but client_assertion is missing",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "private_key_jwt"},
			form:      url.Values{"client_id": []string{"foo"}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidRequest,
		},
		{
			d:         "should fail because client_assertion_type is unknown",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "private_key_jwt"},
			form:      url.Values{"client_id": []string{"foo"}, "client_assertion_type": []string{"foobar"}},
			r:         new(http.Request),
			expectErr: ErrInvalidRequest,
		},
		{
			d:      "should pass with proper assertion when JWKs are set within the client and client_id is not set in the request",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: jwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_assertion": {mustGenerateAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, key, "kid-foo")}, "client_assertion_type": []string{at}},
			r: new(http.Request),
		},
		{
			d:      "should fail because token auth method is not private_key_jwt",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: jwks, TokenEndpointAuthMethod: "client_secret_jwt"},
			form: url.Values{"client_assertion": {mustGenerateAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, key, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should pass with proper assertion when JWKs are set within the client and client_id is not set in the request (aud is array)",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: jwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_assertion": {mustGenerateAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour),
				"iss": "bar",
				"jti": "12345",
				"aud": []string{"token-url-2", "token-url"},
			}, key, "kid-foo")}, "client_assertion_type": []string{at}},
			r: new(http.Request),
		},
		{
			d:      "should fail because audience (array) does not match token url",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: jwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_assertion": {mustGenerateAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour),
				"iss": "bar",
				"jti": "12345",
				"aud": []string{"token-url-1", "token-url-2"},
			}, key, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should pass with proper assertion when JWKs are set within the client",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: jwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, key, "kid-foo")}, "client_assertion_type": []string{at}},
			r: new(http.Request),
		},
		{
			d:      "should fail because JWT algorithm is HS256",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: jwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateHSAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, key, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should fail because JWT algorithm is none",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: jwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateNoneAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, key, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should pass with proper assertion when JWKs URI is set",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeysURI: ts.URL, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, key, "kid-foo")}, "client_assertion_type": []string{at}},
			r: new(http.Request),
		},
		{
			d:      "should fail because client_assertion sub does not match client",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: jwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateAssertion(t, jwt.MapClaims{
				"sub": "not-bar",
				"exp": time.Now().Add(time.Hour),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, key, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should fail because client_assertion iss does not match client",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: jwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour),
				"iss": "not-bar",
				"jti": "12345",
				"aud": "token-url",
			}, key, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should fail because client_assertion jti is not set",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: jwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour),
				"iss": "bar",
				"aud": "token-url",
			}, key, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should fail because client_assertion aud is not set",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: jwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour),
				"iss": "bar",
				"jti": "12345",
				"aud": "not-token-url",
			}, key, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.d), func(t *testing.T) {
			store := storage.NewMemoryStore()
			store.Clients[tc.client.ID] = tc.client
			f.Store = store

			c, err := f.AuthenticateClient(nil, tc.r, tc.form)
			if tc.expectErr != nil {
				require.EqualError(t, err, tc.expectErr.Error())
				return
			}

			if err != nil {
				switch e := errors.Cause(err).(type) {
				case *jwt.ValidationError:
					t.Logf("Error is: %s", e.Inner)
				case *RFC6749Error:
					t.Logf("Debug is: %s", e.Debug)
				}
			}
			require.NoError(t, err)
			assert.EqualValues(t, tc.client, c)
		})
	}
}
