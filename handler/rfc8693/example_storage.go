package rfc8693

import (
	"context"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

// ExampleStorage provides an example implementation of RFC8693Storage
// This is a basic implementation for demonstration purposes.
// In production, you should implement proper token validation and storage.
type ExampleStorage struct {
	AccessTokenStorage  oauth2.AccessTokenStorage
	RefreshTokenStorage oauth2.RefreshTokenStorage
	AccessTokenStrategy oauth2.AccessTokenStrategy
}

// ValidateSubjectToken validates the subject token and returns token information
func (s *ExampleStorage) ValidateSubjectToken(ctx context.Context, token string, tokenType string, client fosite.Client) (*TokenInfo, error) {
	switch tokenType {
	case TokenTypeAccessToken:
		return s.validateAccessToken(ctx, token, client)
	case TokenTypeRefreshToken:
		return s.validateRefreshToken(ctx, token, client)
	default:
		return nil, fmt.Errorf("unsupported token type: %s", tokenType)
	}
}

// ValidateActorToken validates the actor token and returns token information
func (s *ExampleStorage) ValidateActorToken(ctx context.Context, token string, tokenType string, client fosite.Client) (*TokenInfo, error) {
	// Actor tokens use the same validation logic as subject tokens
	return s.ValidateSubjectToken(ctx, token, tokenType, client)
}

// StoreTokenExchange stores the token exchange information for auditing
func (s *ExampleStorage) StoreTokenExchange(ctx context.Context, request *TokenExchangeRequest, response *TokenExchangeResponse) error {
	// In a real implementation, you would store this information for auditing purposes
	// For example, in a database table with columns for:
	// - timestamp
	// - client_id
	// - subject_token_info
	// - actor_token_info (if present)
	// - issued_token_info
	// - scopes
	// - audiences
	
	// This is a no-op implementation for demonstration
	return nil
}

// validateAccessToken validates an access token and returns token information
func (s *ExampleStorage) validateAccessToken(ctx context.Context, token string, client fosite.Client) (*TokenInfo, error) {
	// Use the access token strategy to get the signature
	signature := s.AccessTokenStrategy.AccessTokenSignature(ctx, token)
	
	req, err := s.AccessTokenStorage.GetAccessTokenSession(ctx, signature, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	session := req.GetSession()
	
	// Extract token information
	tokenInfo := &TokenInfo{
		Subject:   session.GetSubject(),
		Scopes:    req.GetGrantedScopes(),
		Audiences: req.GetGrantedAudience(),
		TokenType: TokenTypeAccessToken,
		Extra:     make(map[string]interface{}),
	}

	// Check if token is expired (this is usually handled by the storage layer)
	// but we include it here for completeness
	if session.GetExpiresAt(fosite.AccessToken).Before(time.Now().UTC()) {
		return nil, fmt.Errorf("access token is expired")
	}

	return tokenInfo, nil
}

// validateRefreshToken validates a refresh token and returns token information
func (s *ExampleStorage) validateRefreshToken(ctx context.Context, token string, client fosite.Client) (*TokenInfo, error) {
	// For refresh tokens, we might need to use a different strategy
	// This is a simplified implementation - in practice, you may need to handle
	// refresh tokens differently based on your token strategy
	signature := s.AccessTokenStrategy.AccessTokenSignature(ctx, token)
	
	req, err := s.RefreshTokenStorage.GetRefreshTokenSession(ctx, signature, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	session := req.GetSession()
	
	// Extract token information
	tokenInfo := &TokenInfo{
		Subject:   session.GetSubject(),
		Scopes:    req.GetGrantedScopes(),
		Audiences: req.GetGrantedAudience(),
		TokenType: TokenTypeRefreshToken,
		Extra:     make(map[string]interface{}),
	}

	// Check if token is expired
	if session.GetExpiresAt(fosite.RefreshToken).Before(time.Now().UTC()) {
		return nil, fmt.Errorf("refresh token is expired")
	}

	return tokenInfo, nil
}
