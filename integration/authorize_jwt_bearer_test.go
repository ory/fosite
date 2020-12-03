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
	"golang.org/x/oauth2"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	goauth_jwt "golang.org/x/oauth2/jwt"
)

type authorizeJWTBearerSuite struct {
	suite.Suite

	client *goauth_jwt.Config
}

func (s *authorizeJWTBearerSuite) getClient() *goauth_jwt.Config {
	client := *s.client

	return &client
}

func (s *authorizeJWTBearerSuite) assertSuccessResponse(t *testing.T, token *oauth2.Token, err error) {
	assert.Nil(t, err)
	assert.NotNil(t, token)

	assert.Equal(t, token.TokenType, "bearer")
	assert.Empty(t, token.RefreshToken)
	assert.NotEmpty(t, token.Expiry)
	assert.NotEmpty(t, token.AccessToken)
}

func (s *authorizeJWTBearerSuite) TestBaseConfiguredClient() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.TokenSource(ctx).Token()

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestGetTokenWithoutScopes() {
	ctx := context.Background()
	client := s.getClient()
	client.Scopes = nil

	token, err := client.TokenSource(ctx).Token()

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestGetTokenWithRandomClaim() {
	ctx := context.Background()
	client := s.getClient()
	client.PrivateClaims = map[string]interface{}{"random": "random"}

	token, err := client.TokenSource(ctx).Token()

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestGetTokenWithNoteBeforeClaim() {
	ctx := context.Background()
	client := s.getClient()
	client.PrivateClaims = map[string]interface{}{"nbf": time.Now().Add(-time.Hour).Unix()}

	token, err := client.TokenSource(ctx).Token()

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestGetTokenWithJTIClaim() {
	ctx := context.Background()
	client := s.getClient()
	client.PrivateClaims = map[string]interface{}{"jti": "unique-string-1234"}

	token, err := client.TokenSource(ctx).Token()

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestGetTokenWithAllSuccessCases() {
	ctx := context.Background()
	client := s.getClient()
	client.Scopes = nil
	client.PrivateClaims = map[string]interface{}{
		"nbf":    time.Now().Add(-time.Hour).Unix(),
		"jti":    "another-unique-string-1234",
		"random": "random",
	}

	token, err := client.TokenSource(ctx).Token()

	s.assertSuccessResponse(s.T(), token, err)
}

func TestAuthorizeJWTBearerSuite(t *testing.T) {
	provider := compose.Compose(
		&compose.Config{
			JWTSkipClientAuth: true,
			JWTIDOptional: true,
			JWTIssuedDateOptional: true,
			TokenURL: "https://www.ory.sh/api",
		},
		fositeStore,
		hmacStrategy,
		nil,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2AuthorizeJWTGrantFactory,
	)
	testServer := mockServer(t, provider, &fosite.DefaultSession{})
	defer testServer.Close()

	suite.Run(t, &authorizeJWTBearerSuite{
		client: newOAuth2JWTBearerAppClient(testServer),
	})
}
