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

package clients

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

const jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

type JWTBearer struct {
	tokenURL string
	header   *Header
	client   *http.Client

	PrivateKey   *rsa.PrivateKey
	PrivateKeyID string
}

type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
}

type Header struct {
	Algorithm string `json:"alg"`
	Typ       string `json:"typ"`
	KeyID     string `json:"kid,omitempty"`
}

type JWTBearerPayload struct {
	Issuer   string
	Subject  string
	Audience []string
	Expires  int64

	IssuerAt      int64
	NotBefore     int64
	JWTID         string
	PrivateClaims map[string]interface{}
}

func (c *JWTBearer) SetPrivateKey(keyID string, privateKey *rsa.PrivateKey) {
	c.PrivateKey = privateKey
	c.header = &Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     keyID,
	}
}

func (c *JWTBearer) GetToken(ctx context.Context, payloadData *JWTBearerPayload, scope []string) (*Token, error) {
	requestBodyReader, err := c.getRequestBodyReader(payloadData, scope)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, "POST", c.tokenURL, requestBodyReader)
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if c := response.StatusCode; c < 200 || c > 299 {
		return nil, &RequestError{
			Response: response,
			Body:     body,
		}
	}

	token := &Token{}

	if err := json.Unmarshal(body, token); err != nil {
		return nil, err
	}

	return token, err
}

func (c *JWTBearer) getRequestBodyReader(payloadData *JWTBearerPayload, scope []string) (io.Reader, error) {
	assertion, err := c.getAssertion(payloadData)
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("grant_type", jwtBearerGrantType)
	data.Set("assertion", string(assertion))

	if len(scope) != 0 {
		data.Set("scope", strings.Join(scope, " "))
	}

	return strings.NewReader(data.Encode()), nil
}

func (c *JWTBearer) getAssertion(payloadData *JWTBearerPayload) ([]byte, error) {
	payload, err := c.getBase64Payload(payloadData)
	if err != nil {
		return nil, err
	}

	headerJSON, err := json.Marshal(c.header)
	if err != nil {
		return nil, err
	}

	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	firstPart := []byte(fmt.Sprintf("%s.%s", header, payload))

	h := sha256.New()
	h.Write(firstPart)

	singed, err := rsa.SignPKCS1v15(rand.Reader, c.PrivateKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return nil, err
	}

	return []byte(fmt.Sprintf("%s.%s", firstPart, base64.RawURLEncoding.EncodeToString(singed))), nil
}

func (c *JWTBearer) getBase64Payload(payload *JWTBearerPayload) (string, error) {
	payloadMap := map[string]interface{}{
		"iss": payload.Issuer,
		"sub": payload.Subject,
		"aud": payload.Audience,
		"exp": payload.Expires,
	}

	if payload.IssuerAt > 0 {
		payloadMap["iat"] = payload.IssuerAt
	}

	if payload.NotBefore > 0 {
		payloadMap["nbf"] = payload.NotBefore
	}

	if payload.JWTID != "" {
		payloadMap["jti"] = payload.JWTID
	}

	if len(payload.PrivateClaims) != 0 {
		for claim, value := range payload.PrivateClaims {
			payloadMap[claim] = value
		}
	}

	payloadString, err := json.Marshal(payloadMap)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(payloadString), nil
}

func NewJWTBearer(tokenURL string) *JWTBearer {
	return &JWTBearer{
		client:   &http.Client{},
		tokenURL: tokenURL,
	}
}
