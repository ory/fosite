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

type authorizeJWTBearerSuite struct {
	suite.Suite

	client *clients.JWTBearer
}

func (s *authorizeJWTBearerSuite) getClient() *clients.JWTBearer {
	client := *s.client

	return &client
}

func (s *authorizeJWTBearerSuite) assertSuccessResponse(t *testing.T, token *clients.Token, err error) {
	assert.Nil(t, err)
	assert.NotNil(t, token)

	assert.Equal(t, token.TokenType, "bearer")
	assert.Empty(t, token.RefreshToken)
	assert.NotEmpty(t, token.ExpiresIn)
	assert.NotEmpty(t, token.AccessToken)
}

func (s *authorizeJWTBearerSuite) assertBadRequestResponse(t *testing.T, token *clients.Token, err error) {
	assert.Nil(t, token)
	assert.NotNil(t, err)

	retrieveError, ok := err.(*clients.RequestError)
	assert.True(t, ok)
	assert.Equal(t, retrieveError.Response.StatusCode, http.StatusBadRequest)
}

func (s *authorizeJWTBearerSuite) TestBaseConfiguredClient() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:   firstJWTBearerIssuer,
		Subject:  firstJWTBearerSubject,
		Audience: []string{"https://www.ory.sh/api"},
		Expires:  time.Now().Add(time.Hour).Unix(),
		IssuerAt: time.Now().Unix(),
	}, []string{"fosite"})

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestListOfAudience() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:   firstJWTBearerIssuer,
		Subject:  firstJWTBearerSubject,
		Audience: []string{"https://www.ory.sh/api", "https://vk.com/oauth"},
		Expires:  time.Now().Add(time.Hour).Unix(),
		IssuerAt: time.Now().Unix(),
	}, []string{"fosite"})

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestFewScopes() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:   firstJWTBearerIssuer,
		Subject:  firstJWTBearerSubject,
		Audience: []string{"https://www.ory.sh/api"},
		Expires:  time.Now().Add(time.Hour).Unix(),
		IssuerAt: time.Now().Unix(),
	}, []string{"fosite", "gitlab"})

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestGetTokenWithoutScopes() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:   firstJWTBearerIssuer,
		Subject:  firstJWTBearerSubject,
		Audience: []string{"https://www.ory.sh/api"},
		Expires:  time.Now().Add(time.Hour).Unix(),
		IssuerAt: time.Now().Unix(),
	}, nil)

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestGetTokenWithRandomClaim() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:        firstJWTBearerIssuer,
		Subject:       firstJWTBearerSubject,
		Audience:      []string{"https://www.ory.sh/api"},
		Expires:       time.Now().Add(time.Hour).Unix(),
		IssuerAt:      time.Now().Unix(),
		PrivateClaims: map[string]interface{}{"random": "random"},
	}, []string{"fosite"})

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestGetTokenWithNotBeforeClaim() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:    firstJWTBearerIssuer,
		Subject:   firstJWTBearerSubject,
		Audience:  []string{"https://www.ory.sh/api"},
		Expires:   time.Now().Add(time.Hour).Unix(),
		IssuerAt:  time.Now().Unix(),
		NotBefore: time.Now().Add(-time.Hour).Unix(),
	}, []string{"fosite"})

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestGetTokenWithJTIClaim() {
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

func (s *authorizeJWTBearerSuite) TestGetTokenWithAllSuccessCases() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:        firstJWTBearerIssuer,
		Subject:       firstJWTBearerSubject,
		Audience:      []string{"https://www.ory.sh/api"},
		Expires:       time.Now().Add(time.Hour).Unix(),
		IssuerAt:      time.Now().Unix(),
		JWTID:         uuid.New(),
		NotBefore:     time.Now().Add(-time.Hour).Unix(),
		PrivateClaims: map[string]interface{}{"random": "random"},
	}, nil)

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestExpiredJWT() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:   firstJWTBearerIssuer,
		Subject:  firstJWTBearerSubject,
		Audience: []string{"https://www.ory.sh/api"},
		Expires:  time.Now().Add(-time.Hour).Unix(),
		IssuerAt: time.Now().Unix(),
	}, []string{"fosite"})

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestMaxDuration() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:   firstJWTBearerIssuer,
		Subject:  firstJWTBearerSubject,
		Audience: []string{"https://www.ory.sh/api"},
		Expires:  time.Now().Add(365 * 24 * time.Hour).Unix(),
		IssuerAt: time.Now().Unix(),
	}, []string{"fosite"})

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestInvalidPrivatKey() {
	ctx := context.Background()
	client := s.getClient()
	client.SetPrivateKey(firstKeyID, secondPrivateKey)
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:   firstJWTBearerIssuer,
		Subject:  firstJWTBearerSubject,
		Audience: []string{"https://www.ory.sh/api"},
		Expires:  time.Now().Add(time.Hour).Unix(),
		IssuerAt: time.Now().Unix(),
	}, nil)

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestInvalidKeyID() {
	ctx := context.Background()
	client := s.getClient()
	client.SetPrivateKey(secondKeyID, firstPrivateKey)
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:   firstJWTBearerIssuer,
		Subject:  firstJWTBearerSubject,
		Audience: []string{"https://www.ory.sh/api"},
		Expires:  time.Now().Add(time.Hour).Unix(),
		IssuerAt: time.Now().Unix(),
	}, nil)

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestInvalidAudience() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:   firstJWTBearerIssuer,
		Subject:  firstJWTBearerSubject,
		Audience: []string{"https://vk.com/oauth"},
		Expires:  time.Now().Add(time.Hour).Unix(),
		IssuerAt: time.Now().Unix(),
	}, nil)

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestDuplicatedJTI() {
	ctx := context.Background()
	client := s.getClient()
	config := &clients.JWTBearerPayload{
		Issuer:   firstJWTBearerIssuer,
		Subject:  firstJWTBearerSubject,
		Audience: []string{"https://www.ory.sh/api"},
		Expires:  time.Now().Add(time.Hour).Unix(),
		IssuerAt: time.Now().Unix(),
		JWTID:    uuid.New(),
	}

	client.GetToken(ctx, config, nil)
	token2, err := client.GetToken(ctx, config, nil)

	s.assertBadRequestResponse(s.T(), token2, err)
}

func (s *authorizeJWTBearerSuite) TestNotBeforeLaterThenIssueAt() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:    firstJWTBearerIssuer,
		Subject:   firstJWTBearerSubject,
		Audience:  []string{"https://www.ory.sh/api"},
		Expires:   time.Now().Add(time.Hour).Unix(),
		IssuerAt:  time.Now().Unix(),
		NotBefore: time.Now().Add(time.Hour).Unix(),
	}, nil)

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestWithoutIssuer() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:   firstJWTBearerIssuer,
		Subject:  "",
		Audience: []string{"https://www.ory.sh/api"},
		Expires:  time.Now().Add(time.Hour).Unix(),
		IssuerAt: time.Now().Unix(),
	}, nil)

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestWithWrongSubject() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:   firstJWTBearerIssuer,
		Subject:  secondJWTBearerIssuer,
		Audience: []string{"https://www.ory.sh/api"},
		Expires:  time.Now().Add(time.Hour).Unix(),
		IssuerAt: time.Now().Unix(),
	}, nil)

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestWithWrongIssuer() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:   secondJWTBearerIssuer,
		Subject:  firstJWTBearerSubject,
		Audience: []string{"https://www.ory.sh/api"},
		Expires:  time.Now().Add(time.Hour).Unix(),
		IssuerAt: time.Now().Unix(),
	}, nil)

	s.assertBadRequestResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestWithWrongScope() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Issuer:   firstJWTBearerIssuer,
		Subject:  firstJWTBearerSubject,
		Audience: []string{"https://www.ory.sh/api"},
		Expires:  time.Now().Add(time.Hour).Unix(),
		IssuerAt: time.Now().Unix(),
	}, []string{"fosite", "lenovo"})

	s.assertBadRequestResponse(s.T(), token, err)
}

func TestAuthorizeJWTBearerSuite(t *testing.T) {
	provider := compose.Compose(
		&compose.Config{
			JWTSkipClientAuth:     true,
			JWTIDOptional:         true,
			JWTIssuedDateOptional: true,
			JWTMaxDuration:        24 * time.Hour,
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

	suite.Run(t, &authorizeJWTBearerSuite{
		client: client,
	})
}
