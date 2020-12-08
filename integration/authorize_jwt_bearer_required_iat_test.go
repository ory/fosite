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
	"time"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/integration/clients"
)

type authorizeJWTBearerRequiredAITSuite struct {
	suite.Suite

	client *clients.JWTBearer
}

func (s *authorizeJWTBearerRequiredAITSuite) getClient() *clients.JWTBearer {
	client := *s.client

	return &client
}

func (s *authorizeJWTBearerRequiredAITSuite) assertSuccessResponse(t *testing.T, token *clients.Token, err error) {
	assert.Nil(t, err)
	assert.NotNil(t, token)

	assert.Equal(t, token.TokenType, "bearer")
	assert.Empty(t, token.RefreshToken)
	assert.NotEmpty(t, token.ExpiresIn)
	assert.NotEmpty(t, token.AccessToken)
}

func (s *authorizeJWTBearerRequiredAITSuite) assertBadRequestResponse(t *testing.T, token *clients.Token, err error) {
	assert.Nil(t, token)
	assert.NotNil(t, err)

	retrieveError, ok := err.(*clients.RequestError)
	assert.True(t, ok)
	assert.Equal(t, retrieveError.Response.StatusCode, http.StatusBadRequest)
}

func (s *authorizeJWTBearerRequiredAITSuite) TestBaseConfiguredClient() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:   firstJWTBearerIssuer,
		Subject:  firstJWTBearerSubject,
		Audience: []string{"https://www.ory.sh/api"},
		Expires:  time.Now().Add(time.Hour).Unix(),
		JWTID:    uuid.New(),
	}, []string{"fosite"})

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerRequiredAITSuite) TestWithJTIClaim() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:   firstJWTBearerIssuer,
		Subject:  firstJWTBearerSubject,
		Audience: []string{"https://www.ory.sh/api"},
		Expires:  time.Now().Add(time.Hour).Unix(),
		IssuerAt: time.Now().Unix(),
		JWTID:    uuid.New(),
	}, []string{"fosite"})

	s.assertSuccessResponse(s.T(), token, err)
}

func TestAuthorizeJWTBearerRequiredAITSuite(t *testing.T) {
	provider := compose.Compose(
		&compose.Config{
			JWTSkipClientAuth:     true,
			JWTIDOptional:         true,
			JWTIssuedDateOptional: false,
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

	client := newJWTBearerAppClient(testServer)
	client.SetPrivateKey(firstKeyID, firstPrivateKey)

	suite.Run(t, &authorizeJWTBearerRequiredAITSuite{
		client: client,
	})
}
