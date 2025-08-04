package rfc8693

import (
	"context"

	"github.com/ory/fosite"
)

// TokenInfo contains information about a validated token
type TokenInfo struct {
	// Subject is the subject identifier
	Subject string

	// Scopes are the scopes associated with the token
	Scopes fosite.Arguments

	// Audiences are the intended audiences for the token
	Audiences fosite.Arguments

	// Extra contains additional token information
	Extra map[string]interface{}

	// ExpiresAt is the token expiration time (Unix timestamp)
	ExpiresAt int64

	// IssuedAt is the token issuance time (Unix timestamp)
	IssuedAt int64

	// TokenType is the type of the token
	TokenType string
}

// RFC8693Storage defines the storage interface for RFC 8693 Token Exchange
type RFC8693Storage interface {
	// ValidateSubjectToken validates the subject token and returns token information
	ValidateSubjectToken(ctx context.Context, token string, tokenType string, client fosite.Client) (*TokenInfo, error)

	// ValidateActorToken validates the actor token and returns token information
	ValidateActorToken(ctx context.Context, token string, tokenType string, client fosite.Client) (*TokenInfo, error)

	// StoreTokenExchange stores the token exchange information for auditing
	StoreTokenExchange(ctx context.Context, request *TokenExchangeRequest, response *TokenExchangeResponse) error
}
