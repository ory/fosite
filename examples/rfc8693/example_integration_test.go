package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/rfc8693"
	"github.com/ory/fosite/storage"
)

func TestTokenExchangeClientAuthentication(t *testing.T) {
	// Setup the OAuth2 provider with RFC 8693 support
	store := &ExampleStorage{
		MemoryStore: storage.NewMemoryStore(),
	}

	config := &fosite.Config{
		AccessTokenLifespan:   time.Hour,
		RefreshTokenLifespan:  time.Hour * 24 * 30,
		AuthorizeCodeLifespan: time.Minute * 15,
		GlobalSecret:          []byte("test-global-secret-32-bytes-long"),

		// Enable RFC 8693 Token Exchange
		TokenExchangeEnabled: true,
		TokenExchangeTokenTypes: []string{
			rfc8693.TokenTypeAccessToken,
			rfc8693.TokenTypeRefreshToken,
		},

		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
	}

	oauth2Provider := compose.Compose(
		config,
		store,
		compose.NewOAuth2HMACStrategy(config),

		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2AuthorizeImplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.RFC8693TokenExchangeFactory,
	)

	// Create and store a test client with hashed secret
	client := &fosite.DefaultClient{
		ID:     "test-client",
		Secret: []byte("$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO"), // = "foobar"
		GrantTypes: fosite.Arguments{
			"authorization_code",
			"refresh_token",
			"client_credentials",
			rfc8693.GrantTypeTokenExchange,
		},
		ResponseTypes: fosite.Arguments{"code", "token"},
		Scopes:        fosite.Arguments{"read", "write", "admin"},
		Audience:      fosite.Arguments{"api.example.com"},
	}
	store.MemoryStore.Clients["test-client"] = client

	t.Run("successful token exchange with HTTP Basic Auth", func(t *testing.T) {
		form := url.Values{}
		form.Set("grant_type", rfc8693.GrantTypeTokenExchange)
		form.Set("subject_token", "valid-access-token")
		form.Set("subject_token_type", rfc8693.TokenTypeAccessToken)
		form.Set("scope", "read")

		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// Set HTTP Basic Auth header
		auth := base64.StdEncoding.EncodeToString([]byte("test-client:foobar"))
		req.Header.Set("Authorization", "Basic "+auth)

		recorder := httptest.NewRecorder()
		handleTokenEndpoint(recorder, req, oauth2Provider)

		assert.Equal(t, http.StatusOK, recorder.Code)

		response := recorder.Body.String()
		assert.Contains(t, response, "access_token")
		assert.Contains(t, response, "token_type")
		assert.Contains(t, response, "issued_token_type")
		assert.Contains(t, response, rfc8693.TokenTypeAccessToken)
	})

	t.Run("successful token exchange with form-based auth", func(t *testing.T) {
		form := url.Values{}
		form.Set("grant_type", rfc8693.GrantTypeTokenExchange)
		form.Set("subject_token", "valid-access-token")
		form.Set("subject_token_type", rfc8693.TokenTypeAccessToken)
		form.Set("scope", "read")
		form.Set("client_id", "test-client")
		form.Set("client_secret", "foobar")

		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		recorder := httptest.NewRecorder()
		handleTokenEndpoint(recorder, req, oauth2Provider)

		assert.Equal(t, http.StatusOK, recorder.Code)

		response := recorder.Body.String()
		assert.Contains(t, response, "access_token")
		assert.Contains(t, response, "token_type")
		assert.Contains(t, response, "issued_token_type")
		assert.Contains(t, response, rfc8693.TokenTypeAccessToken)
	})

	t.Run("HTTP Basic Auth takes precedence over form params", func(t *testing.T) {
		form := url.Values{}
		form.Set("grant_type", rfc8693.GrantTypeTokenExchange)
		form.Set("subject_token", "valid-access-token")
		form.Set("subject_token_type", rfc8693.TokenTypeAccessToken)
		form.Set("scope", "read")
		// Set WRONG form-based credentials
		form.Set("client_id", "wrong-client")
		form.Set("client_secret", "wrong-secret")

		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// Set CORRECT HTTP Basic Auth header
		auth := base64.StdEncoding.EncodeToString([]byte("test-client:foobar"))
		req.Header.Set("Authorization", "Basic "+auth)

		recorder := httptest.NewRecorder()
		handleTokenEndpoint(recorder, req, oauth2Provider)

		// Should succeed because Basic Auth takes precedence and is correct
		assert.Equal(t, http.StatusOK, recorder.Code)

		response := recorder.Body.String()
		assert.Contains(t, response, "access_token")
	})

	t.Run("invalid HTTP Basic Auth credentials", func(t *testing.T) {
		form := url.Values{}
		form.Set("grant_type", rfc8693.GrantTypeTokenExchange)
		form.Set("subject_token", "valid-access-token")
		form.Set("subject_token_type", rfc8693.TokenTypeAccessToken)

		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// Set invalid HTTP Basic Auth header
		auth := base64.StdEncoding.EncodeToString([]byte("wrong-client:wrong-secret"))
		req.Header.Set("Authorization", "Basic "+auth)

		recorder := httptest.NewRecorder()
		handleTokenEndpoint(recorder, req, oauth2Provider)

		assert.Equal(t, http.StatusUnauthorized, recorder.Code)
		response := recorder.Body.String()
		assert.Contains(t, response, "error")
	})

	t.Run("malformed Basic Auth header", func(t *testing.T) {
		form := url.Values{}
		form.Set("grant_type", rfc8693.GrantTypeTokenExchange)
		form.Set("subject_token", "valid-access-token")
		form.Set("subject_token_type", rfc8693.TokenTypeAccessToken)

		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic invalid-base64!")

		recorder := httptest.NewRecorder()
		handleTokenEndpoint(recorder, req, oauth2Provider)

		assert.Equal(t, http.StatusBadRequest, recorder.Code)
		response := recorder.Body.String()
		assert.Contains(t, response, "error")
	})
}

func TestExampleStorage(t *testing.T) {
	store := &ExampleStorage{
		MemoryStore: storage.NewMemoryStore(),
	}

	client := &fosite.DefaultClient{
		ID:     "test-client",
		Secret: []byte("test-secret"),
		Scopes: fosite.Arguments{"read", "write"},
	}

	ctx := context.Background()

	t.Run("validate subject access token", func(t *testing.T) {
		tokenInfo, err := store.ValidateSubjectToken(ctx, "test-access-token", rfc8693.TokenTypeAccessToken, client)

		require.NoError(t, err)
		assert.Equal(t, "user123", tokenInfo.Subject)
		assert.Equal(t, fosite.Arguments{"read", "write"}, tokenInfo.Scopes)
		assert.Equal(t, fosite.Arguments{"api.example.com"}, tokenInfo.Audiences)
		assert.Equal(t, rfc8693.TokenTypeAccessToken, tokenInfo.TokenType)
		assert.True(t, tokenInfo.ExpiresAt > time.Now().Unix())
	})

	t.Run("validate subject refresh token", func(t *testing.T) {
		tokenInfo, err := store.ValidateSubjectToken(ctx, "test-refresh-token", rfc8693.TokenTypeRefreshToken, client)

		require.NoError(t, err)
		assert.Equal(t, "user123", tokenInfo.Subject)
		assert.Equal(t, fosite.Arguments{"read", "write"}, tokenInfo.Scopes)
		assert.Equal(t, fosite.Arguments{"api.example.com"}, tokenInfo.Audiences)
		assert.Equal(t, rfc8693.TokenTypeRefreshToken, tokenInfo.TokenType)
		assert.True(t, tokenInfo.ExpiresAt > time.Now().Unix())
	})

	t.Run("validate actor token", func(t *testing.T) {
		tokenInfo, err := store.ValidateActorToken(ctx, "test-actor-token", rfc8693.TokenTypeAccessToken, client)

		require.NoError(t, err)
		assert.Equal(t, "user123", tokenInfo.Subject)
		assert.Equal(t, rfc8693.TokenTypeAccessToken, tokenInfo.TokenType)
	})

	t.Run("unsupported token type", func(t *testing.T) {
		_, err := store.ValidateSubjectToken(ctx, "test-token", "unsupported-type", client)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported token type")
	})

	t.Run("store token exchange", func(t *testing.T) {
		request := &rfc8693.TokenExchangeRequest{
			SubjectToken:     "subject-token",
			SubjectTokenType: rfc8693.TokenTypeAccessToken,
			SubjectTokenInfo: &rfc8693.TokenInfo{
				Subject:   "user123",
				TokenType: rfc8693.TokenTypeAccessToken,
			},
		}

		response := &rfc8693.TokenExchangeResponse{
			AccessToken:     "new-access-token",
			IssuedTokenType: rfc8693.TokenTypeAccessToken,
			TokenType:       "Bearer",
		}

		err := store.StoreTokenExchange(ctx, request, response)
		assert.NoError(t, err)
	})
}
