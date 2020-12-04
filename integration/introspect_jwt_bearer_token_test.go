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

package integration_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/parnurzeal/gorequest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	goauth_jwt "golang.org/x/oauth2/jwt"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
)

type responseIntrospect struct {
	Active    bool     `json:"active"`
	ClientID  string   `json:"client_id,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Username  string   `json:"username,omitempty"`
}

type introspectJwtBearerTokenSuite struct {
	suite.Suite

	clientJWT *goauth_jwt.Config
	clientAppJWT *goauth_jwt.Config
	clientIntrospect *gorequest.SuperAgent
}

func (s *introspectJwtBearerTokenSuite) getClient() *goauth_jwt.Config {
	client := *s.clientJWT

	return &client
}

func (s *introspectJwtBearerTokenSuite) getClientApp() *goauth_jwt.Config {
	client := *s.clientAppJWT

	return &client
}

func (s *introspectJwtBearerTokenSuite) introspectAccessToken(
	accessToken,
	scopes string,
	headers map[string]string,
) (*responseIntrospect, []error) {
	res := &responseIntrospect{}
	client := *s.clientIntrospect
	request := client.
		Type("form").
		SendStruct(map[string]string{"token": accessToken, "scope": scopes})

	for key, value := range headers {
		request.Set(key, value)
	}

	_, bytes, errs := request.End()
	if errs != nil {
		return nil, errs
	}

	if err := json.Unmarshal([]byte(bytes), res); err != nil {
		return nil, []error{err}
	}

	return res, nil
}

func (s *introspectJwtBearerTokenSuite) assertSuccessResponse(t *testing.T, response *responseIntrospect, err []error) {
	assert.Nil(t, err)
	assert.NotNil(t, response)

	assert.True(t, response.Active)
	assert.Equal(t, response.Subject, firstJWTBearerSubject)
	assert.NotEmpty(t, response.ExpiresAt)
	assert.NotEmpty(t, response.IssuedAt)
	// TODO understood about ClientID Scope Audience Username
}

func (s *introspectJwtBearerTokenSuite) TestBaseConfiguredClient() {
	ctx := context.Background()
	token, _ := s.getClient().TokenSource(ctx).Token()
	token2, _ := s.getClientApp().TokenSource(ctx).Token()

	response, err := s.introspectAccessToken(
		token.AccessToken,
		"",
		map[string]string{ "Authorization": "bearer "+ token2.AccessToken},
	)

	s.assertSuccessResponse(s.T(), response, err)
}

func TestIntrospectJwtBearerTokenSuite(t *testing.T) {
	provider := compose.Compose(
		&compose.Config{
			JWTSkipClientAuth:     true,
			JWTIDOptional:         true,
			JWTIssuedDateOptional: true,
			TokenURL:              "https://www.ory.sh/api",
		},
		fositeStore,
		jwtStrategy,
		nil,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2AuthorizeJWTGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)
	testServer := mockServer(t, provider, &fosite.DefaultSession{})
	defer testServer.Close()

	suite.Run(t, &introspectJwtBearerTokenSuite{
		clientJWT: newJWTBearerAppFirstClient(testServer),
		clientAppJWT: newJWTBearerAppSecondClient(testServer),
		clientIntrospect: gorequest.New().Post(testServer.URL + "/introspect"),
	})
}
