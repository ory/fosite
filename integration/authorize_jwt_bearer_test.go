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
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"golang.org/x/oauth2"
	goauth_jwt "golang.org/x/oauth2/jwt"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
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

func (s *authorizeJWTBearerSuite) assertBadRequestResponse(t *testing.T, token *oauth2.Token, err error) {
	assert.Nil(t, token)
	assert.NotNil(t, err)

	retrieveError, ok := err.(*oauth2.RetrieveError)
	assert.True(t, ok)
	assert.Equal(t, retrieveError.Response.StatusCode, http.StatusBadRequest)
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
	client.PrivateClaims = map[string]interface{}{"jti": uuid.New()}

	token, err := client.TokenSource(ctx).Token()

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestGetTokenWithAllSuccessCases() {
	ctx := context.Background()
	client := s.getClient()
	client.Scopes = nil
	client.PrivateClaims = map[string]interface{}{
		"nbf":    time.Now().Add(-time.Hour).Unix(),
		"jti":    uuid.New(),
		"random": "random",
	}

	token, err := client.TokenSource(ctx).Token()

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestInvalidPrivatKey() {
	ctx := context.Background()
	client := s.getClient()
	client.PrivateKey = x509.MarshalPKCS1PrivateKey(secondPrivateKey)

	token, err := client.TokenSource(ctx).Token()

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestInvalidKeyID() {
	ctx := context.Background()
	client := s.getClient()
	client.PrivateKeyID = secondKeyID

	token, err := client.TokenSource(ctx).Token()

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestInvalidAudience() {
	ctx := context.Background()
	client := s.getClient()
	client.Audience = "https://vk.com/oauth"

	token, err := client.TokenSource(ctx).Token()

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestDuplicatedJTI() {
	ctx := context.Background()
	client := s.getClient()
	client.PrivateClaims = map[string]interface{}{"jti": uuid.New()}
	client.TokenSource(ctx).Token()

	token, err := client.TokenSource(ctx).Token()

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestDuplicatedJTIInSameTime() {
	ctx := context.Background()
	client := s.getClient()
	client.PrivateClaims = map[string]interface{}{"jti": uuid.New()}
	client.TokenSource(ctx).Token()

	token, err := client.TokenSource(ctx).Token()

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestNotBeforeLaterThenIssueAt() {
	ctx := context.Background()
	client := s.getClient()
	client.PrivateClaims = map[string]interface{}{"nbf": time.Now().Add(time.Hour).Unix()}

	token, err := client.TokenSource(ctx).Token()

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestNotBeforeInvalidFormat() {
	ctx := context.Background()
	client := s.getClient()
	client.PrivateClaims = map[string]interface{}{"nbf": time.Now().Add(-time.Hour).Format(time.RFC3339)}

	token, err := client.TokenSource(ctx).Token()

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestWithoutIssuer() {
	ctx := context.Background()
	client := s.getClient()
	client.Email = ""

	token, err := client.TokenSource(ctx).Token()

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestWrongRegisteredIssuer() {
	ctx := context.Background()
	client := s.getClient()
	client.Email = secondJWTBearerIssuer

	token, err := client.TokenSource(ctx).Token()

	s.assertBadRequestResponse(s.T(), token, err)
}

func TestAuthorizeJWTBearerSuite(t *testing.T) {
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
	)
	testServer := mockServer(t, provider, &fosite.DefaultSession{})
	defer testServer.Close()

	suite.Run(t, &authorizeJWTBearerSuite{
		client: newJWTBearerAppFirstClient(testServer),
	})
}
