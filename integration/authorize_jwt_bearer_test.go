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
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/integration/clients"
)

type authorizeJWTBearerSuite struct {
	suite.Suite

	client *clients.JWTBearer
}

func (s *authorizeJWTBearerSuite) TestSuccessResponseWithRequiredParamsOnly() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}, []string{"fosite"})

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestSuccessResponseWithMultipleAudienceInAssertion() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL, "https://example.com/oauth"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}, []string{"fosite"})

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestSuccessResponseWithMultipleScopesInRequest() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}, []string{"fosite", "gitlab"})

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestSuccessResponseWithoutScopes() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}, nil)

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestSuccessResponseWithExtraClaim() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		PrivateClaims: map[string]interface{}{"extraClaim": "extraClaimValue"},
	}, []string{"fosite"})

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestSuccessResponseWithNotBeforeClaim() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:    firstJWTBearerIssuer,
			Subject:   firstJWTBearerSubject,
			Audience:  []string{tokenURL},
			Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}, []string{"fosite"})

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestSuccessResponseWithJTIClaim() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
			ID:       uuid.New(),
		},
	}, []string{"fosite"})

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestSuccessResponse() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:    firstJWTBearerIssuer,
			Subject:   firstJWTBearerSubject,
			Audience:  []string{tokenURL, "example.com"},
			Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			ID:        uuid.New(),
		},
		PrivateClaims: map[string]interface{}{"random": "random"},
	}, nil)

	s.assertSuccessResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestBadResponseWithExpiredJWT() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}, []string{"fosite"})

	s.assertBadResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestBadResponseWithExpiryMaxDuration() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(365 * 24 * time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}, []string{"fosite"})

	s.assertBadResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestBadResponseWithInvalidPrivateKey() {
	ctx := context.Background()
	client := s.getClient()
	wrongPrivateKey := secondPrivateKey

	if err := client.SetPrivateKey(firstKeyID, wrongPrivateKey); err != nil {
		assert.Nil(s.T(), err)
	}

	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}, nil)

	s.assertBadResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestBadResponseWithInvalidKeyID() {
	ctx := context.Background()
	client := s.getClient()

	if err := client.SetPrivateKey("wrongKeyID", firstPrivateKey); err != nil {
		assert.Nil(s.T(), err)
	}

	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}, nil)

	s.assertBadResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestBadResponseWithInvalidAudience() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{"https://example.com/oauth"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}, nil)

	s.assertBadResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestBadResponseForSecondRequestWithSameJTI() {
	ctx := context.Background()
	client := s.getClient()
	config := &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
			ID:       uuid.New(),
		},
	}

	client.GetToken(ctx, config, nil)
	token2, err := client.GetToken(ctx, config, nil)

	s.assertBadResponse(s.T(), token2, err)
}

func (s *authorizeJWTBearerSuite) TestSuccessResponseForSecondRequestWithSameJTIAfterFirstExpired() {
	ctx := context.Background()
	client := s.getClient()
	config := &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Second)),
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			ID:       uuid.New(),
		},
	}

	client.GetToken(ctx, config, nil)

	time.Sleep(time.Second)
	config.Expiry = jwt.NewNumericDate(time.Now().Add(time.Hour))

	token2, err := client.GetToken(ctx, config, nil)

	s.assertSuccessResponse(s.T(), token2, err)
}

func (s *authorizeJWTBearerSuite) TestBadResponseWithNotBeforeLaterThenIssueAt() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:    firstJWTBearerIssuer,
			Subject:   firstJWTBearerSubject,
			Audience:  []string{tokenURL},
			Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}, nil)

	s.assertBadResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestBadResponseWithoutSubject() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  "",
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}, nil)

	s.assertBadResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestBadResponseWithWrongSubject() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  "wrong_subject",
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}, nil)

	s.assertBadResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestBadResponseWithWrongIssuer() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   "wrong_issuer",
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}, nil)

	s.assertBadResponse(s.T(), token, err)
}

func (s *authorizeJWTBearerSuite) TestBadResponseWithWrongScope() {
	ctx := context.Background()
	client := s.getClient()
	token, err := client.GetToken(ctx, &clients.JWTBearerPayload{
		Claims: &jwt.Claims{
			Issuer:   firstJWTBearerIssuer,
			Subject:  firstJWTBearerSubject,
			Audience: []string{tokenURL},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}, []string{"fosite", "permission"})

	s.assertBadResponse(s.T(), token, err)
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

func (s *authorizeJWTBearerSuite) assertBadResponse(t *testing.T, token *clients.Token, err error) {
	assert.Nil(t, token)
	assert.NotNil(t, err)

	retrieveError, ok := err.(*clients.RequestError)
	assert.True(t, ok)
	assert.Equal(t, retrieveError.Response.StatusCode, http.StatusBadRequest)
}

func TestAuthorizeJWTBearerSuite(t *testing.T) {
	provider := compose.Compose(
		&compose.Config{
			JWTSkipClientAuth:     true,
			JWTIDOptional:         true,
			JWTIssuedDateOptional: true,
			JWTMaxDuration:        24 * time.Hour,
			TokenURL:              tokenURL,
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
	if err := client.SetPrivateKey(firstKeyID, firstPrivateKey); err != nil {
		assert.Nil(t, err)
	}

	suite.Run(t, &authorizeJWTBearerSuite{
		client: client,
	})
}
