// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	mrand "math/rand"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite/handler/oauth2"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/suite"
	gomock "go.uber.org/mock/gomock"

	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
)

// Define the suite, and absorb the built-in basic suite
// functionality from testify - including a T() method which
// returns the current testing context.
type AuthorizeJWTGrantRequestHandlerTestSuite struct {
	suite.Suite

	privateKey              *rsa.PrivateKey
	mockCtrl                *gomock.Controller
	mockStore               *internal.MockRFC7523KeyStorage
	mockAccessTokenStrategy *internal.MockAccessTokenStrategy
	mockAccessTokenStore    *internal.MockAccessTokenStorage
	accessRequest           *fosite.AccessRequest
	handler                 *Handler
}

// Setup before each test in the suite.
func (s *AuthorizeJWTGrantRequestHandlerTestSuite) SetupSuite() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 512) // fast RSA for testing
	if err != nil {
		s.FailNowf("failed to setup test suite", "failed to generate RSA private key: %s", err.Error())
	}
	s.privateKey = privateKey
}

// Will run after all the tests in the suite have been run.
func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TearDownSuite() {
}

// Will run after each test in the suite.
func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TearDownTest() {
	s.mockCtrl.Finish()
}

// Setup before each test.
func (s *AuthorizeJWTGrantRequestHandlerTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockStore = internal.NewMockRFC7523KeyStorage(s.mockCtrl)
	s.mockAccessTokenStrategy = internal.NewMockAccessTokenStrategy(s.mockCtrl)
	s.mockAccessTokenStore = internal.NewMockAccessTokenStorage(s.mockCtrl)
	s.accessRequest = fosite.NewAccessRequest(new(fosite.DefaultSession))
	s.accessRequest.Form = url.Values{}
	s.accessRequest.Client = &fosite.DefaultClient{GrantTypes: []string{grantTypeJWTBearer}}
	s.handler = &Handler{
		Storage: s.mockStore,
		Config: &fosite.Config{
			ScopeStrategy:                        fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy:             fosite.DefaultAudienceMatchingStrategy,
			TokenURL:                             "https://www.example.com/token",
			GrantTypeJWTBearerCanSkipClientAuth:  false,
			GrantTypeJWTBearerIDOptional:         false,
			GrantTypeJWTBearerIssuedDateOptional: false,
			GrantTypeJWTBearerMaxDuration:        time.Hour * 24 * 30,
		},
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStrategy: s.mockAccessTokenStrategy,
			AccessTokenStorage:  s.mockAccessTokenStore,
			Config: &fosite.Config{
				AccessTokenLifespan: time.Hour,
			},
		},
	}
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run.
func TestAuthorizeJWTGrantRequestHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(AuthorizeJWTGrantRequestHandlerTestSuite))
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestRequestWithInvalidGrantType() {
	// arrange
	s.accessRequest.GrantTypes = []string{"authorization_code"}

	// act
	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrUnknownRequest))
	s.EqualError(err, fosite.ErrUnknownRequest.Error(), "expected error, because of invalid grant type")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestClientIsNotRegisteredForGrantType() {
	// arrange
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	s.accessRequest.Client = &fosite.DefaultClient{GrantTypes: []string{"authorization_code"}}
	s.handler.Config.(*fosite.Config).GrantTypeJWTBearerCanSkipClientAuth = false

	// act
	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrUnauthorizedClient))
	s.EqualError(err, fosite.ErrUnauthorizedClient.Error(), "expected error, because client is not registered to use this grant type")
	s.Equal(
		"The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:jwt-bearer\".",
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestRequestWithoutAssertion() {
	// arrange
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}

	// act
	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidRequest))
	s.EqualError(err, fosite.ErrInvalidRequest.Error(), "expected error, because of missing assertion")
	s.Equal(
		"The assertion request parameter must be set when using grant_type of 'urn:ietf:params:oauth:grant-type:jwt-bearer'.",
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestRequestWithMalformedAssertion() {
	// arrange
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	s.accessRequest.Form.Add("assertion", "fjigjgfkjgkf")

	// act
	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because of malformed assertion")
	s.Equal(
		"Unable to parse JSON Web Token passed in \"assertion\" request parameter.",
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestRequestAssertionWithoutIssuer() {
	// arrange
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	cl := s.createStandardClaim()
	cl.Issuer = ""
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))

	// act
	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because of missing issuer claim in assertion")
	s.Equal(
		"The JWT in \"assertion\" request parameter MUST contain an \"iss\" (issuer) claim.",
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestRequestAssertionWithoutSubject() {
	// arrange
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	cl := s.createStandardClaim()
	cl.Subject = ""
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))

	// act
	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because of missing subject claim in assertion")
	s.Equal(
		"The JWT in \"assertion\" request parameter MUST contain a \"sub\" (subject) claim.",
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestNoMatchingPublicKeyToCheckAssertionSignature() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	cl := s.createStandardClaim()
	keyID := "my_key"
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(nil, fosite.ErrNotFound)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because of missing public key to check assertion")
	s.Equal(
		fmt.Sprintf(
			"No public JWK was registered for issuer \"%s\" and subject \"%s\", and public key is required to check signature of JWT in \"assertion\" request parameter.",
			cl.Issuer, cl.Subject,
		),
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestNoMatchingPublicKeysToCheckAssertionSignature() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "" // provide no hint of what key was used to sign assertion
	cl := s.createStandardClaim()
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKeys(ctx, cl.Issuer, cl.Subject).Return(nil, fosite.ErrNotFound)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because of missing public keys to check assertion")
	s.Equal(
		fmt.Sprintf(
			"No public JWK was registered for issuer \"%s\" and subject \"%s\", and public key is required to check signature of JWT in \"assertion\" request parameter.",
			cl.Issuer, cl.Subject,
		),
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestWrongPublicKeyToCheckAssertionSignature() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "wrong_key"
	cl := s.createStandardClaim()
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	jwk := s.createRandomTestJWK()
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&jwk, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because wrong public key was registered for assertion")
	s.Equal("Unable to verify the integrity of the 'assertion' value.", fosite.ErrorToRFC6749Error(err).HintField)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestWrongPublicKeysToCheckAssertionSignature() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "" // provide no hint of what key was used to sign assertion
	cl := s.createStandardClaim()
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKeys(ctx, cl.Issuer, cl.Subject).Return(s.createJWS(s.createRandomTestJWK(), s.createRandomTestJWK()), nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because wrong public keys was registered for assertion")
	s.Equal(
		fmt.Sprintf(
			"No public JWK was registered for issuer \"%s\" and subject \"%s\", and public key is required to check signature of JWT in \"assertion\" request parameter.",
			cl.Issuer, cl.Subject,
		),
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestNoAudienceInAssertion() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.Audience = []string{}
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because of missing audience claim in assertion")
	s.Equal(
		"The JWT in \"assertion\" request parameter MUST contain an \"aud\" (audience) claim.",
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestNotValidAudienceInAssertion() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.Audience = jwt.Audience{"leela", "fry"}
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because of invalid audience claim in assertion")
	s.Equal(
		fmt.Sprintf(
			`The JWT in "assertion" request parameter MUST contain an "aud" (audience) claim containing a value "%s" that identifies the authorization server as an intended audience.`,
			strings.Join(s.handler.Config.GetTokenURLs(ctx), `" or "`),
		),
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestNoExpirationInAssertion() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.Expiry = nil
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because of missing expiration claim in assertion")
	s.Equal(
		"The JWT in \"assertion\" request parameter MUST contain an \"exp\" (expiration time) claim.",
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestExpiredAssertion() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.Expiry = jwt.NewNumericDate(time.Now().AddDate(0, -1, 0))
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because assertion expired")
	s.Equal(
		"The JWT in \"assertion\" request parameter expired.",
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionNotAcceptedBeforeDate() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	nbf := time.Now().AddDate(0, 1, 0)
	cl := s.createStandardClaim()
	cl.NotBefore = jwt.NewNumericDate(nbf)
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, nbf claim in assertion indicates, that assertion can not be accepted now")
	s.Equal(
		fmt.Sprintf(
			"The JWT in \"assertion\" request parameter contains an \"nbf\" (not before) claim, that identifies the time '%s' before which the token MUST NOT be accepted.",
			nbf.Format(time.RFC3339),
		),
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionWithoutRequiredIssueDate() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.IssuedAt = nil
	s.handler.Config.(*fosite.Config).GrantTypeJWTBearerIssuedDateOptional = false
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because of missing iat claim in assertion")
	s.Equal(
		"The JWT in \"assertion\" request parameter MUST contain an \"iat\" (issued at) claim.",
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionWithIssueDateFarInPast() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	issuedAt := time.Now().AddDate(0, 0, -31)
	cl := s.createStandardClaim()
	cl.IssuedAt = jwt.NewNumericDate(issuedAt)
	s.handler.Config.(*fosite.Config).GrantTypeJWTBearerIssuedDateOptional = false
	s.handler.Config.(*fosite.Config).GrantTypeJWTBearerMaxDuration = time.Hour * 24 * 30
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because assertion was issued far in the past")
	s.Equal(
		fmt.Sprintf(
			"The JWT in \"assertion\" request parameter contains an \"exp\" (expiration time) claim with value \"%s\" that is unreasonably far in the future, considering token issued at \"%s\".",
			cl.Expiry.Time().Format(time.RFC3339),
			cl.IssuedAt.Time().Format(time.RFC3339),
		),
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionWithExpirationDateFarInFuture() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.IssuedAt = jwt.NewNumericDate(time.Now().AddDate(0, 0, -15))
	cl.Expiry = jwt.NewNumericDate(time.Now().AddDate(0, 0, 20))
	s.handler.Config.(*fosite.Config).GrantTypeJWTBearerIssuedDateOptional = false
	s.handler.Config.(*fosite.Config).GrantTypeJWTBearerMaxDuration = time.Hour * 24 * 30
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because assertion will expire unreasonably far in the future.")
	s.Equal(
		fmt.Sprintf(
			"The JWT in \"assertion\" request parameter contains an \"exp\" (expiration time) claim with value \"%s\" that is unreasonably far in the future, considering token issued at \"%s\".",
			cl.Expiry.Time().Format(time.RFC3339),
			cl.IssuedAt.Time().Format(time.RFC3339),
		),
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionWithExpirationDateFarInFutureWithNoIssuerDate() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.IssuedAt = nil
	cl.Expiry = jwt.NewNumericDate(time.Now().AddDate(0, 0, 31))
	s.handler.Config.(*fosite.Config).GrantTypeJWTBearerIssuedDateOptional = true
	s.handler.Config.(*fosite.Config).GrantTypeJWTBearerMaxDuration = time.Hour * 24 * 30
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because assertion will expire unreasonably far in the future.")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionWithoutRequiredTokenID() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.ID = ""
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because of missing jti claim in assertion")
	s.Equal(
		"The JWT in \"assertion\" request parameter MUST contain an \"jti\" (JWT ID) claim.",
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionAlreadyUsed() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().IsJWTUsed(ctx, cl.ID).Return(true, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrJTIKnown))
	s.EqualError(err, fosite.ErrJTIKnown.Error(), "expected error, because assertion was used")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestErrWhenCheckingIfJWTWasUsed() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().IsJWTUsed(ctx, cl.ID).Return(false, fosite.ErrServerError)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrServerError))
	s.EqualError(err, fosite.ErrServerError.Error(), "expected error, because error occurred while trying to check if jwt was used")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestErrWhenMarkingJWTAsUsed() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetPublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
	s.mockStore.EXPECT().IsJWTUsed(ctx, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().MarkJWTUsedForTime(ctx, cl.ID, cl.Expiry.Time()).Return(fosite.ErrServerError)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrServerError))
	s.EqualError(err, fosite.ErrServerError.Error(), "expected error, because error occurred while trying to mark jwt as used")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestErrWhileFetchingPublicKeyScope() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()

	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetPublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{}, fosite.ErrServerError)
	s.mockStore.EXPECT().IsJWTUsed(ctx, cl.ID).Return(false, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrServerError))
	s.EqualError(err, fosite.ErrServerError.Error(), "expected error, because error occurred while fetching public key scopes")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionWithInvalidScopes() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()

	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.accessRequest.RequestedScope = []string{"some_scope"}
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetPublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
	s.mockStore.EXPECT().IsJWTUsed(ctx, cl.ID).Return(false, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidScope))
	s.EqualError(err, fosite.ErrInvalidScope.Error(), "expected error, because requested scopes don't match allowed scope for this assertion")
	s.Equal(
		"The public key registered for issuer \"trusted_issuer\" and subject \"some_ro\" is not allowed to request scope \"some_scope\".",
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestValidAssertion() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()

	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.accessRequest.RequestedScope = []string{"valid_scope"}
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetPublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope", "openid"}, nil)
	s.mockStore.EXPECT().IsJWTUsed(ctx, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().MarkJWTUsedForTime(ctx, cl.ID, cl.Expiry.Time()).Return(nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.NoError(err, "no error expected, because assertion must be valid")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionIsValidWhenNoScopesPassed() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetPublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
	s.mockStore.EXPECT().IsJWTUsed(ctx, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().MarkJWTUsedForTime(ctx, cl.ID, cl.Expiry.Time()).Return(nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.NoError(err, "no error expected, because assertion must be valid")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionIsValidWhenJWTIDIsOptional() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.handler.Config.(*fosite.Config).GrantTypeJWTBearerIDOptional = true
	cl.ID = ""
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetPublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.NoError(err, "no error expected, because assertion must be valid, when no jti claim and it is allowed by option")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestAssertionIsValidWhenJWTIssuedDateOptional() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.IssuedAt = nil
	s.handler.Config.(*fosite.Config).GrantTypeJWTBearerIssuedDateOptional = true
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetPublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
	s.mockStore.EXPECT().IsJWTUsed(ctx, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().MarkJWTUsedForTime(ctx, cl.ID, cl.Expiry.Time()).Return(nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.NoError(err, "no error expected, because assertion must be valid, when no iss claim and it is allowed by option")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) TestRequestIsValidWhenClientAuthOptional() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.accessRequest.Client = &fosite.DefaultClient{}
	s.handler.Config.(*fosite.Config).GrantTypeJWTBearerCanSkipClientAuth = true
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetPublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
	s.mockStore.EXPECT().IsJWTUsed(ctx, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().MarkJWTUsedForTime(ctx, cl.ID, cl.Expiry.Time()).Return(nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.NoError(err, "no error expected, because request must be valid, when no client unauthenticated and it is allowed by option")
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) createTestAssertion(cl jwt.Claims, keyID string) string {
	jwk := jose.JSONWebKey{Key: s.privateKey, KeyID: keyID, Algorithm: string(jose.RS256)}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		s.FailNowf("failed to create test assertion", "failed to create signer: %s", err.Error())
	}

	raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
	if err != nil {
		s.FailNowf("failed to create test assertion", "failed to sign assertion: %s", err.Error())
	}

	return raw
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) createStandardClaim() jwt.Claims {
	return jwt.Claims{
		Issuer:    "trusted_issuer",
		Subject:   "some_ro",
		Audience:  jwt.Audience{"https://www.example.com/token", "leela", "fry"},
		Expiry:    jwt.NewNumericDate(time.Now().UTC().AddDate(0, 0, 23)),
		NotBefore: nil,
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC().AddDate(0, 0, -7)),
		ID:        "my_token",
	}
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) createRandomTestJWK() jose.JSONWebKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s.FailNowf("failed to create random test JWK", "failed to generate RSA private key: %s", err.Error())
	}

	return s.createJWK(privateKey.Public(), strconv.Itoa(mrand.Int()))
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) createJWK(key interface{}, keyID string) jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       key,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
}

func (s *AuthorizeJWTGrantRequestHandlerTestSuite) createJWS(keys ...jose.JSONWebKey) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: keys}
}

// Define the suite, and absorb the built-in basic suite
// functionality from testify - including a T() method which
// returns the current testing context.
type AuthorizeJWTGrantPopulateTokenEndpointTestSuite struct {
	suite.Suite

	privateKey              *rsa.PrivateKey
	mockCtrl                *gomock.Controller
	mockStore               *internal.MockRFC7523KeyStorage
	mockAccessTokenStrategy *internal.MockAccessTokenStrategy
	mockAccessTokenStore    *internal.MockAccessTokenStorage
	accessRequest           *fosite.AccessRequest
	accessResponse          *fosite.AccessResponse
	handler                 *Handler
}

// Setup before each test in the suite.
func (s *AuthorizeJWTGrantPopulateTokenEndpointTestSuite) SetupSuite() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s.FailNowf("failed to setup test suite", "failed to generate RSA private key: %s", err.Error())
	}
	s.privateKey = privateKey
}

// Will run after all the tests in the suite have been run.
func (s *AuthorizeJWTGrantPopulateTokenEndpointTestSuite) TearDownSuite() {
}

// Will run after each test in the suite.
func (s *AuthorizeJWTGrantPopulateTokenEndpointTestSuite) TearDownTest() {
	s.mockCtrl.Finish()
}

// Setup before each test.
func (s *AuthorizeJWTGrantPopulateTokenEndpointTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockStore = internal.NewMockRFC7523KeyStorage(s.mockCtrl)
	s.mockAccessTokenStrategy = internal.NewMockAccessTokenStrategy(s.mockCtrl)
	s.mockAccessTokenStore = internal.NewMockAccessTokenStorage(s.mockCtrl)
	s.accessRequest = fosite.NewAccessRequest(new(fosite.DefaultSession))
	s.accessRequest.Form = url.Values{}
	s.accessRequest.Client = &fosite.DefaultClient{GrantTypes: []string{grantTypeJWTBearer}}
	s.accessResponse = fosite.NewAccessResponse()
	s.handler = &Handler{
		Storage: s.mockStore,
		Config: &fosite.Config{
			ScopeStrategy:                        fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy:             fosite.DefaultAudienceMatchingStrategy,
			TokenURL:                             "https://www.example.com/token",
			GrantTypeJWTBearerCanSkipClientAuth:  false,
			GrantTypeJWTBearerIDOptional:         false,
			GrantTypeJWTBearerIssuedDateOptional: false,
			GrantTypeJWTBearerMaxDuration:        time.Hour * 24 * 30,
		},
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStrategy: s.mockAccessTokenStrategy,
			AccessTokenStorage:  s.mockAccessTokenStore,
			Config: &fosite.Config{
				AccessTokenLifespan: time.Hour,
			},
		},
	}
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run.
func TestAuthorizeJWTGrantPopulateTokenEndpointTestSuite(t *testing.T) {
	suite.Run(t, new(AuthorizeJWTGrantPopulateTokenEndpointTestSuite))
}

func (s *AuthorizeJWTGrantPopulateTokenEndpointTestSuite) TestRequestWithInvalidGrantType() {
	// arrange
	s.accessRequest.GrantTypes = []string{"authorization_code"}

	// act
	err := s.handler.PopulateTokenEndpointResponse(context.Background(), s.accessRequest, s.accessResponse)

	// assert
	s.True(errors.Is(err, fosite.ErrUnknownRequest))
	s.EqualError(err, fosite.ErrUnknownRequest.Error(), "expected error, because of invalid grant type")
}

func (s *AuthorizeJWTGrantPopulateTokenEndpointTestSuite) TestClientIsNotRegisteredForGrantType() {
	// arrange
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	s.accessRequest.Client = &fosite.DefaultClient{GrantTypes: []string{"authorization_code"}}
	s.handler.Config.(*fosite.Config).GrantTypeJWTBearerCanSkipClientAuth = false

	// act
	err := s.handler.PopulateTokenEndpointResponse(context.Background(), s.accessRequest, s.accessResponse)

	// assert
	s.True(errors.Is(err, fosite.ErrUnauthorizedClient))
	s.EqualError(err, fosite.ErrUnauthorizedClient.Error(), "expected error, because client is not registered to use this grant type")
	s.Equal(
		"The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:jwt-bearer\".",
		fosite.ErrorToRFC6749Error(err).HintField,
	)
}

func (s *AuthorizeJWTGrantPopulateTokenEndpointTestSuite) TestAccessTokenIssuedSuccessfully() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	token := "token"
	sig := "sig"
	s.mockAccessTokenStrategy.EXPECT().GenerateAccessToken(ctx, s.accessRequest).Return(token, sig, nil)
	s.mockAccessTokenStore.EXPECT().CreateAccessTokenSession(ctx, sig, s.accessRequest.Sanitize([]string{}))

	// act
	err := s.handler.PopulateTokenEndpointResponse(context.Background(), s.accessRequest, s.accessResponse)

	// assert
	s.NoError(err, "no error expected")
	s.Equal(s.accessResponse.AccessToken, token, "access token expected in response")
	s.Equal(s.accessResponse.TokenType, "bearer", "token type expected to be \"bearer\"")
	s.Equal(
		s.accessResponse.GetExtra("expires_in"), int64(s.handler.HandleHelper.Config.GetAccessTokenLifespan(context.TODO()).Seconds()),
		"token expiration time expected in response to be equal to AccessTokenLifespan setting in handler",
	)
	s.Equal(s.accessResponse.GetExtra("scope"), "", "no scopes expected in response")
	s.Nil(s.accessResponse.GetExtra("refresh_token"), "refresh token not expected in response")
}

func (s *AuthorizeJWTGrantPopulateTokenEndpointTestSuite) TestAccessTokenIssuedSuccessfullyWithCustomLifespan() {
	s.accessRequest.Client = &fosite.DefaultClientWithCustomTokenLifespans{
		DefaultClient: &fosite.DefaultClient{
			GrantTypes: []string{grantTypeJWTBearer},
		},
		TokenLifespans: &internal.TestLifespans,
	}
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJWTBearer}
	token := "token"
	sig := "sig"
	s.mockAccessTokenStrategy.EXPECT().GenerateAccessToken(ctx, s.accessRequest).Return(token, sig, nil)
	s.mockAccessTokenStore.EXPECT().CreateAccessTokenSession(ctx, sig, s.accessRequest.Sanitize([]string{}))

	// act
	err := s.handler.PopulateTokenEndpointResponse(context.Background(), s.accessRequest, s.accessResponse)

	// assert
	s.NoError(err, "no error expected")
	s.Equal(s.accessResponse.AccessToken, token, "access token expected in response")
	s.Equal(s.accessResponse.TokenType, "bearer", "token type expected to be \"bearer\"")
	s.Equal(
		s.accessResponse.GetExtra("expires_in"), int64(internal.TestLifespans.JwtBearerGrantAccessTokenLifespan.Seconds()),
		"token expiration time expected in response to be equal to the pertinent AccessTokenLifespan setting in client",
	)
	s.Equal(s.accessResponse.GetExtra("scope"), "", "no scopes expected in response")
	s.Nil(s.accessResponse.GetExtra("refresh_token"), "refresh token not expected in response")
}
