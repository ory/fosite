package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	mrand "math/rand"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/suite"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
)

// Define the suite, and absorb the built-in basic suite
// functionality from testify - including a T() method which
// returns the current testing context.
type AuthorizeJwtGrantRequestHandlerTestSuite struct {
	suite.Suite

	privateKey              *rsa.PrivateKey
	mockCtrl                *gomock.Controller
	mockStore               *internal.MockAuthorizeJwtGrantStorage
	mockAccessTokenStrategy *internal.MockAccessTokenStrategy
	mockAccessTokenStore    *internal.MockAccessTokenStorage
	accessRequest           *fosite.AccessRequest
	handler                 *AuthorizeJwtGrantHandler
}

// Setup before each test in the suite.
func (s *AuthorizeJwtGrantRequestHandlerTestSuite) SetupSuite() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s.FailNowf("failed to setup test suite", "failed to generate RSA private key: %s", err.Error())
	}
	s.privateKey = privateKey
}

// Will run after all the tests in the suite have been run.
func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TearDownSuite() {
}

// Will run after each test in the suite.
func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TearDownTest() {
	s.mockCtrl.Finish()
}

// Setup before each test.
func (s *AuthorizeJwtGrantRequestHandlerTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockStore = internal.NewMockAuthorizeJwtGrantStorage(s.mockCtrl)
	s.mockAccessTokenStrategy = internal.NewMockAccessTokenStrategy(s.mockCtrl)
	s.mockAccessTokenStore = internal.NewMockAccessTokenStorage(s.mockCtrl)
	s.accessRequest = fosite.NewAccessRequest(new(fosite.DefaultSession))
	s.accessRequest.Form = url.Values{}
	s.accessRequest.Client = &fosite.DefaultClient{GrantTypes: []string{grantTypeJwtBearer}}
	s.handler = &AuthorizeJwtGrantHandler{
		AuthorizeJwtGrantStorage: s.mockStore,
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		TokenURL:                 "https://www.example.com/token",
		SkipClientAuth:           false,
		JWTIDOptional:            false,
		JWTIssuedDateOptional:    false,
		JWTMaxDuration:           time.Hour * 24 * 30,
		HandleHelper: &HandleHelper{
			AccessTokenStrategy: s.mockAccessTokenStrategy,
			AccessTokenStorage:  s.mockAccessTokenStore,
			AccessTokenLifespan: time.Hour,
		},
	}
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run.
func TestAuthorizeJwtGrantRequestHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(AuthorizeJwtGrantRequestHandlerTestSuite))
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestRequestWithInvalidGrantType() {
	// arrange
	s.accessRequest.GrantTypes = []string{"authorization_code"}

	// act
	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrUnknownRequest))
	s.EqualError(err, fosite.ErrUnknownRequest.Error(), "expected error, because of invalid grant type")
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestClientIsNotRegisteredForGrantType() {
	// arrange
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
	s.accessRequest.Client = &fosite.DefaultClient{GrantTypes: []string{"authorization_code"}}
	s.handler.SkipClientAuth = false

	// act
	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrUnauthorizedClient))
	s.EqualError(err, fosite.ErrUnauthorizedClient.Error(), "expected error, because client is not registered to use this grant type")
	s.Equal(
		"The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:jwt-bearer\".",
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestRequestWithoutAssertion() {
	// arrange
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}

	// act
	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidRequest))
	s.EqualError(err, fosite.ErrInvalidRequest.Error(), "expected error, because of missing assertion")
	s.Equal(
		"The assertion request parameter must be set when using grant_type of 'urn:ietf:params:oauth:grant-type:jwt-bearer'.",
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestRequestWithMalformedAssertion() {
	// arrange
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
	s.accessRequest.Form.Add("assertion", "fjigjgfkjgkf")

	// act
	err := s.handler.HandleTokenEndpointRequest(context.Background(), s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because of malformed assertion")
	s.Equal(
		"Unable to parse jwt token passed in \"assertion\" request parameter.",
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestRequestAssertionWithoutIssuer() {
	// arrange
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestRequestAssertionWithoutSubject() {
	// arrange
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestNoMatchingPublicKeyToCheckAssertionSignature() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestNoMatchingPublicKeysToCheckAssertionSignature() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestWrongPublicKeyToCheckAssertionSignature() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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
	s.Equal("Unable to verify the integrity of the 'assertion' value.", err.(*fosite.RFC6749Error).HintField)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestWrongPublicKeysToCheckAssertionSignature() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestNoAudienceInAssertion() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestNotValidAudienceInAssertion() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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
			"The JWT in \"assertion\" request parameter MUST contain an \"aud\" (audience) claim containing a value \"%s\" that identifies the authorization server as an intended audience.",
			s.handler.TokenURL,
		),
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestNoExpirationInAssertion() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestExpiredAssertion() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestAssertionNotAcceptedBeforeDate() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestAssertionWithoutRequiredIssueDate() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.IssuedAt = nil
	s.handler.JWTIssuedDateOptional = false
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because of missing iat claim in assertion")
	s.Equal(
		"The JWT in \"assertion\" request parameter MUST contain an \"iat\" (issued at) claim.",
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestAssertionWithIssueDateFarInPast() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	issuedAt := time.Now().AddDate(0, 0, -31)
	cl := s.createStandardClaim()
	cl.IssuedAt = jwt.NewNumericDate(issuedAt)
	s.handler.JWTIssuedDateOptional = false
	s.handler.JWTMaxDuration = time.Hour * 24 * 30
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because assertion was issued far in the past")
	s.Equal(
		fmt.Sprintf(
			"The JWT in \"assertion\" request parameter contains an \"iat\" (issued at) claim with value \"%s\" that is unreasonably far in the past.",
			issuedAt.Format(time.RFC3339),
		),
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestAssertionWithExpirationDateFarInFuture() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.IssuedAt = jwt.NewNumericDate(time.Now().AddDate(0, 0, -15))
	cl.Expiry = jwt.NewNumericDate(time.Now().AddDate(0, 0, 20))
	s.handler.JWTIssuedDateOptional = false
	s.handler.JWTMaxDuration = time.Hour * 24 * 30
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because assertion will expire unreasonably far in the future.")
	s.Equal(
		fmt.Sprintf(
			"The JWT in \"assertion\" request parameter contains an \"exp\" (expiration time) claim with value \"%s\" that is unreasonably far in the future.",
			cl.Expiry.Time().Format(time.RFC3339),
		),
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestAssertionWithExpirationDateFarInFutureWithNoIssuerDate() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.IssuedAt = nil
	cl.Expiry = jwt.NewNumericDate(time.Now().AddDate(0, 0, 31))
	s.handler.JWTIssuedDateOptional = true
	s.handler.JWTMaxDuration = time.Hour * 24 * 30
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidGrant))
	s.EqualError(err, fosite.ErrInvalidGrant.Error(), "expected error, because assertion will expire unreasonably far in the future.")
	s.Equal(
		fmt.Sprintf(
			"The JWT in \"assertion\" request parameter contains an \"exp\" (expiration time) claim with value \"%s\" that is unreasonably far in the future.",
			cl.Expiry.Time().Format(time.RFC3339),
		),
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestAssertionWithoutRequiredTokenID() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestAssertionAlreadyUsed() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestErrWhenCheckingIfJWTWasUsed() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestErrWhenMarkingJWTAsUsed() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().IsJWTUsed(ctx, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().MarkJWTUsedForTime(ctx, cl.ID, cl.Expiry.Time()).Return(fosite.ErrServerError)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrServerError))
	s.EqualError(err, fosite.ErrServerError.Error(), "expected error, because error occurred while trying to mark jwt as used")
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestErrWhileFetchingPublicKeyScope() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()

	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetPublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{}, fosite.ErrServerError)
	s.mockStore.EXPECT().IsJWTUsed(ctx, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().MarkJWTUsedForTime(ctx, cl.ID, cl.Expiry.Time()).Return(nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrServerError))
	s.EqualError(err, fosite.ErrServerError.Error(), "expected error, because error occurred while fetching public key scopes")
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestAssertionWithInvalidScopes() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()

	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.accessRequest.RequestedScope = []string{"some_scope"}
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetPublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)
	s.mockStore.EXPECT().IsJWTUsed(ctx, cl.ID).Return(false, nil)
	s.mockStore.EXPECT().MarkJWTUsedForTime(ctx, cl.ID, cl.Expiry.Time()).Return(nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.True(errors.Is(err, fosite.ErrInvalidScope))
	s.EqualError(err, fosite.ErrInvalidScope.Error(), "expected error, because requested scopes don't match allowed scope for this assertion")
	s.Equal(
		"The OAuth 2.0 Client is not allowed to request scope 'some_scope'.",
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestValidAssertion() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestAssertionIsValidWhenNoScopesPassed() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestAssertionIsValidWhenJWTIDIsOptional() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.handler.JWTIDOptional = true
	cl.ID = ""
	s.accessRequest.Form.Add("assertion", s.createTestAssertion(cl, keyID))
	s.mockStore.EXPECT().GetPublicKey(ctx, cl.Issuer, cl.Subject, keyID).Return(&pubKey, nil)
	s.mockStore.EXPECT().GetPublicKeyScopes(ctx, cl.Issuer, cl.Subject, keyID).Return([]string{"valid_scope"}, nil)

	// act
	err := s.handler.HandleTokenEndpointRequest(ctx, s.accessRequest)

	// assert
	s.NoError(err, "no error expected, because assertion must be valid, when no jti claim and it is allowed by option")
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestAssertionIsValidWhenJWTIssuedDateOptional() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	cl.IssuedAt = nil
	s.handler.JWTIssuedDateOptional = true
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

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) TestRequestIsValidWhenClientAuthOptional() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
	keyID := "my_key"
	pubKey := s.createJWK(s.privateKey.Public(), keyID)
	cl := s.createStandardClaim()
	s.accessRequest.Client = &fosite.DefaultClient{}
	s.handler.SkipClientAuth = true
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

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) createTestAssertion(cl jwt.Claims, keyID string) string {
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

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) createStandardClaim() jwt.Claims {
	return jwt.Claims{
		Issuer:    "trusted_issuer",
		Subject:   "some_ro",
		Audience:  jwt.Audience{"https://www.example.com/token", "leela", "fry"},
		Expiry:    jwt.NewNumericDate(time.Now().AddDate(0, 0, 23)),
		NotBefore: nil,
		IssuedAt:  jwt.NewNumericDate(time.Now().AddDate(0, 0, -7)),
		ID:        "my_token",
	}
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) createRandomTestJWK() jose.JSONWebKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s.FailNowf("failed to create random test JWK", "failed to generate RSA private key: %s", err.Error())
	}

	return s.createJWK(privateKey.Public(), strconv.Itoa(mrand.Int()))
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) createJWK(key interface{}, keyID string) jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       key,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
}

func (s *AuthorizeJwtGrantRequestHandlerTestSuite) createJWS(keys ...jose.JSONWebKey) *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: keys}
}

// Define the suite, and absorb the built-in basic suite
// functionality from testify - including a T() method which
// returns the current testing context.
type AuthorizeJwtGrantPopulateTokenEndpointTestSuite struct {
	suite.Suite

	privateKey              *rsa.PrivateKey
	mockCtrl                *gomock.Controller
	mockStore               *internal.MockAuthorizeJwtGrantStorage
	mockAccessTokenStrategy *internal.MockAccessTokenStrategy
	mockAccessTokenStore    *internal.MockAccessTokenStorage
	accessRequest           *fosite.AccessRequest
	accessResponse          *fosite.AccessResponse
	handler                 *AuthorizeJwtGrantHandler
}

// Setup before each test in the suite.
func (s *AuthorizeJwtGrantPopulateTokenEndpointTestSuite) SetupSuite() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s.FailNowf("failed to setup test suite", "failed to generate RSA private key: %s", err.Error())
	}
	s.privateKey = privateKey
}

// Will run after all the tests in the suite have been run.
func (s *AuthorizeJwtGrantPopulateTokenEndpointTestSuite) TearDownSuite() {
}

// Will run after each test in the suite.
func (s *AuthorizeJwtGrantPopulateTokenEndpointTestSuite) TearDownTest() {
	s.mockCtrl.Finish()
}

// Setup before each test.
func (s *AuthorizeJwtGrantPopulateTokenEndpointTestSuite) SetupTest() {
	s.mockCtrl = gomock.NewController(s.T())
	s.mockStore = internal.NewMockAuthorizeJwtGrantStorage(s.mockCtrl)
	s.mockAccessTokenStrategy = internal.NewMockAccessTokenStrategy(s.mockCtrl)
	s.mockAccessTokenStore = internal.NewMockAccessTokenStorage(s.mockCtrl)
	s.accessRequest = fosite.NewAccessRequest(new(fosite.DefaultSession))
	s.accessRequest.Form = url.Values{}
	s.accessRequest.Client = &fosite.DefaultClient{GrantTypes: []string{grantTypeJwtBearer}}
	s.accessResponse = fosite.NewAccessResponse()
	s.handler = &AuthorizeJwtGrantHandler{
		AuthorizeJwtGrantStorage: s.mockStore,
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		TokenURL:                 "https://www.example.com/token",
		SkipClientAuth:           false,
		JWTIDOptional:            false,
		JWTIssuedDateOptional:    false,
		JWTMaxDuration:           time.Hour * 24 * 30,
		HandleHelper: &HandleHelper{
			AccessTokenStrategy: s.mockAccessTokenStrategy,
			AccessTokenStorage:  s.mockAccessTokenStore,
			AccessTokenLifespan: time.Hour,
		},
	}
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run.
func TestAuthorizeJwtGrantPopulateTokenEndpointTestSuite(t *testing.T) {
	suite.Run(t, new(AuthorizeJwtGrantPopulateTokenEndpointTestSuite))
}

func (s *AuthorizeJwtGrantPopulateTokenEndpointTestSuite) TestRequestWithInvalidGrantType() {
	// arrange
	s.accessRequest.GrantTypes = []string{"authorization_code"}

	// act
	err := s.handler.PopulateTokenEndpointResponse(context.Background(), s.accessRequest, s.accessResponse)

	// assert
	s.True(errors.Is(err, fosite.ErrUnknownRequest))
	s.EqualError(err, fosite.ErrUnknownRequest.Error(), "expected error, because of invalid grant type")
}

func (s *AuthorizeJwtGrantPopulateTokenEndpointTestSuite) TestClientIsNotRegisteredForGrantType() {
	// arrange
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
	s.accessRequest.Client = &fosite.DefaultClient{GrantTypes: []string{"authorization_code"}}
	s.handler.SkipClientAuth = false

	// act
	err := s.handler.PopulateTokenEndpointResponse(context.Background(), s.accessRequest, s.accessResponse)

	// assert
	s.True(errors.Is(err, fosite.ErrUnauthorizedClient))
	s.EqualError(err, fosite.ErrUnauthorizedClient.Error(), "expected error, because client is not registered to use this grant type")
	s.Equal(
		"The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:jwt-bearer\".",
		err.(*fosite.RFC6749Error).HintField,
	)
}

func (s *AuthorizeJwtGrantPopulateTokenEndpointTestSuite) TestAccessTokenIssuedSuccessfully() {
	// arrange
	ctx := context.Background()
	s.accessRequest.GrantTypes = []string{grantTypeJwtBearer}
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
		s.accessResponse.GetExtra("expires_in"), int64(s.handler.HandleHelper.AccessTokenLifespan.Seconds()),
		"token expiration time expected in response to be equal to AccessTokenLifespan setting in handler",
	)
	s.Equal(s.accessResponse.GetExtra("scope"), "", "no scopes expected in response")
	s.Nil(s.accessResponse.GetExtra("refresh_token"), "refresh token not expected in response")
}
