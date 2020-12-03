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
	"net/http"
	"testing"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
	goauth_jwt "golang.org/x/oauth2/jwt"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
)

type authorizeJWTBearerRequiredJtiSuite struct {
	suite.Suite

	client *goauth_jwt.Config
}

func (s *authorizeJWTBearerRequiredJtiSuite) getClient() *goauth_jwt.Config {
	client := *s.client

	return &client
}

func (s *authorizeJWTBearerRequiredJtiSuite) assertSuccessResponse(t *testing.T, token *oauth2.Token, err error) {
	assert.Nil(t, err)
	assert.NotNil(t, token)

	assert.Equal(t, token.TokenType, "bearer")
	assert.Empty(t, token.RefreshToken)
	assert.NotEmpty(t, token.Expiry)
	assert.NotEmpty(t, token.AccessToken)
}

func (s *authorizeJWTBearerRequiredJtiSuite) assertBadRequestResponse(t *testing.T, token *oauth2.Token, err error) {
	assert.Nil(t, token)
	assert.NotNil(t, err)

	retrieveError, ok := err.(*oauth2.RetrieveError)
	assert.True(t, ok)
	assert.Equal(t, retrieveError.Response.StatusCode, http.StatusBadRequest)
}

func (s *authorizeJWTBearerRequiredJtiSuite) TestBaseConfiguredClient() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.TokenSource(ctx).Token()

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerRequiredJtiSuite) TestWithJTIClaim() {
	ctx := context.Background()
	client := s.getClient()
	client.PrivateClaims = map[string]interface{}{"jti": uuid.New()}

	token, err := client.TokenSource(ctx).Token()

	s.assertSuccessResponse(s.T(), token, err)
}

func TestAuthorizeJWTBearerRequiredJtiSuite(t *testing.T) {
	provider := compose.Compose(
		&compose.Config{
			JWTSkipClientAuth:     true,
			JWTIDOptional:         false,
			JWTIssuedDateOptional: true,
			TokenURL:              "https://www.ory.sh/api",
		},
		fositeStore,
		jwtStrategy,
		nil,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2AuthorizeJWTGrantFactory,
	)
	testServer := mockServer(t, provider, &fosite.DefaultSession{})
	defer testServer.Close()

	suite.Run(t, &authorizeJWTBearerRequiredJtiSuite{
		client: newOAuth2JWTBearerAppClient(testServer),
	})
}
