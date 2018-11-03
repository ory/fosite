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

package fosite

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	jose "gopkg.in/square/go-jose.v2"
)

func mustGenerateAssertion(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey, kid string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)
	return tokenString
}

func mustGenerateHSAssertion(t *testing.T, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("aaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccddddddddddddddddddddddd"))
	require.NoError(t, err)
	return tokenString
}

func mustGenerateNoneAssertion(t *testing.T, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return tokenString
}

func TestAuthorizeRequestParametersFromOpenIDConnectRequest(t *testing.T) {

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID: "kid-foo",
				Use:   "sig",
				Key:   &key.PublicKey,
			},
		},
	}

	validRequestObject := mustGenerateAssertion(t, jwt.MapClaims{"scope": "foo", "foo": "bar", "baz": "baz"}, key, "kid-foo")
	validNoneRequestObject := mustGenerateNoneAssertion(t, jwt.MapClaims{"scope": "foo", "foo": "bar", "baz": "baz"})

	var reqH http.HandlerFunc = func(rw http.ResponseWriter, r *http.Request) {
		rw.Write([]byte(validRequestObject))
	}
	reqTS := httptest.NewServer(reqH)
	defer reqTS.Close()

	var hJWK http.HandlerFunc = func(rw http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(rw).Encode(jwks))
	}
	reqJWK := httptest.NewServer(hJWK)
	defer reqJWK.Close()

	f := &Fosite{JWKSFetcherStrategy: NewDefaultJWKSFetcherStrategy()}
	for k, tc := range []struct {
		client Client
		form   url.Values
		d      string

		expectErr  error
		expectForm url.Values
	}{
		{
			d:          "should pass because no request context given and not openid",
			form:       url.Values{},
			expectErr:  nil,
			expectForm: url.Values{},
		},
		{
			d:          "should pass because no request context given",
			form:       url.Values{"scope": {"openid"}},
			expectErr:  nil,
			expectForm: url.Values{"scope": {"openid"}},
		},
		{
			d:          "should pass because request context given but not openid",
			form:       url.Values{"request": {"foo"}},
			expectErr:  nil,
			expectForm: url.Values{"request": {"foo"}},
		},
		{
			d:          "should fail because not an OpenIDConnect compliant client",
			form:       url.Values{"scope": {"openid"}, "request": {"foo"}},
			expectErr:  ErrRequestNotSupported,
			expectForm: url.Values{"scope": {"openid"}},
		},
		{
			d:          "should fail because not an OpenIDConnect compliant client",
			form:       url.Values{"scope": {"openid"}, "request_uri": {"foo"}},
			expectErr:  ErrRequestURINotSupported,
			expectForm: url.Values{"scope": {"openid"}},
		},
		{
			d:          "should fail because token invalid an no keys set",
			form:       url.Values{"scope": {"openid"}, "request_uri": {"foo"}},
			client:     &DefaultOpenIDConnectClient{RequestObjectSigningAlgorithm: "RS256"},
			expectErr:  ErrInvalidRequest,
			expectForm: url.Values{"scope": {"openid"}},
		},
		{
			d:          "should fail because token invalid",
			form:       url.Values{"scope": {"openid"}, "request": {"foo"}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			expectErr:  ErrInvalidRequestObject,
			expectForm: url.Values{"scope": {"openid"}},
		},
		{
			d:          "should fail because kid does not exist",
			form:       url.Values{"scope": {"openid"}, "request": {mustGenerateAssertion(t, jwt.MapClaims{}, key, "does-not-exists")}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			expectErr:  ErrInvalidRequestObject,
			expectForm: url.Values{"scope": {"openid"}},
		},
		{
			d:          "should fail because not RS256 token",
			form:       url.Values{"scope": {"openid"}, "request": {mustGenerateHSAssertion(t, jwt.MapClaims{})}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			expectErr:  ErrInvalidRequestObject,
			expectForm: url.Values{"scope": {"openid"}},
		},
		{
			d:          "should pass and set request parameters properly",
			form:       url.Values{"scope": {"openid"}, "request": {validRequestObject}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeys: jwks, RequestObjectSigningAlgorithm: "RS256"},
			expectForm: url.Values{"scope": {"foo openid"}, "request": {validRequestObject}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			d:          "should fail because request uri is not whitelisted",
			form:       url.Values{"scope": {"openid"}, "request_uri": {reqTS.URL}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeysURI: reqJWK.URL, RequestObjectSigningAlgorithm: "RS256"},
			expectForm: url.Values{"scope": {"foo openid"}, "request_uri": {reqTS.URL}, "foo": {"bar"}, "baz": {"baz"}},
			expectErr:  ErrInvalidRequestURI,
		},
		{
			d:          "should pass and set request_uri parameters properly and also fetch jwk from remote",
			form:       url.Values{"scope": {"openid"}, "request_uri": {reqTS.URL}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeysURI: reqJWK.URL, RequestObjectSigningAlgorithm: "RS256", RequestURIs: []string{reqTS.URL}},
			expectForm: url.Values{"scope": {"foo openid"}, "request_uri": {reqTS.URL}, "foo": {"bar"}, "baz": {"baz"}},
		},
		{
			d:          "should pass when request object uses algorithm none",
			form:       url.Values{"scope": {"openid"}, "request": {validNoneRequestObject}},
			client:     &DefaultOpenIDConnectClient{JSONWebKeysURI: reqJWK.URL, RequestObjectSigningAlgorithm: "none"},
			expectForm: url.Values{"scope": {"foo openid"}, "request": {validNoneRequestObject}, "foo": {"bar"}, "baz": {"baz"}},
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.d), func(t *testing.T) {
			req := &AuthorizeRequest{
				Request: Request{
					Client: tc.client,
					Form:   tc.form,
				},
			}

			err := f.authorizeRequestParametersFromOpenIDConnectRequest(req)
			if tc.expectErr != nil {
				require.EqualError(t, err, tc.expectErr.Error(), "%+v", err)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tc.expectForm), len(req.Form))
				for k, v := range tc.expectForm {
					assert.EqualValues(t, v, req.Form[k])
				}
			}
		})
	}
}
