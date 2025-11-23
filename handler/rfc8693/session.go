// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"time"

	"github.com/ory/fosite"
)

// TokenExchangeRequest represents a token exchange request
type TokenExchangeRequest struct {
	// Subject token information
	SubjectToken     string     `json:"subject_token"`
	SubjectTokenType string     `json:"subject_token_type"`
	SubjectTokenInfo *TokenInfo `json:"subject_token_info"`

	// Actor token information (optional)
	ActorToken     string     `json:"actor_token,omitempty"`
	ActorTokenType string     `json:"actor_token_type,omitempty"`
	ActorTokenInfo *TokenInfo `json:"actor_token_info,omitempty"`

	// Request parameters
	RequestedTokenType string           `json:"requested_token_type,omitempty"`
	Audience           fosite.Arguments `json:"audience,omitempty"`
	Scopes             fosite.Arguments `json:"scopes,omitempty"`
	Resource           string           `json:"resource,omitempty"`
}

// TokenExchangeResponse represents a token exchange response
type TokenExchangeResponse struct {
	// Issued token information
	AccessToken     string           `json:"access_token"`
	IssuedTokenType string           `json:"issued_token_type"`
	TokenType       string           `json:"token_type"`
	ExpiresIn       int64            `json:"expires_in,omitempty"`
	RefreshToken    string           `json:"refresh_token,omitempty"`
	Scope           fosite.Arguments `json:"scope,omitempty"`

	// Additional response parameters
	Extra map[string]interface{} `json:"extra,omitempty"`
}

// TokenExchangeSession implements fosite.Session for token exchange
type TokenExchangeSession struct {
	ExchangeRequest *TokenExchangeRequest          `json:"exchange_request"`
	Subject         string                         `json:"subject"`
	Extra           map[string]interface{}         `json:"extra"`
	ExpiresAt       map[fosite.TokenType]time.Time `json:"expires_at"`
}

// GetSubject returns the subject identifier
func (s *TokenExchangeSession) GetSubject() string {
	return s.Subject
}

// SetSubject sets the subject identifier
func (s *TokenExchangeSession) SetSubject(subject string) {
	s.Subject = subject
}

// GetUsername returns the username (same as subject for token exchange)
func (s *TokenExchangeSession) GetUsername() string {
	return s.Subject
}

// SetExpiresAt sets token expiration
func (s *TokenExchangeSession) SetExpiresAt(key fosite.TokenType, exp time.Time) {
	if s.ExpiresAt == nil {
		s.ExpiresAt = make(map[fosite.TokenType]time.Time)
	}
	s.ExpiresAt[key] = exp
}

// GetExpiresAt returns token expiration
func (s *TokenExchangeSession) GetExpiresAt(key fosite.TokenType) time.Time {
	if s.ExpiresAt == nil {
		return time.Time{}
	}
	return s.ExpiresAt[key]
}

// Clone creates a copy of the session
func (s *TokenExchangeSession) Clone() fosite.Session {
	if s == nil {
		return nil
	}

	extra := make(map[string]interface{})
	for k, v := range s.Extra {
		extra[k] = v
	}

	expiresAt := make(map[fosite.TokenType]time.Time)
	for k, v := range s.ExpiresAt {
		expiresAt[k] = v
	}

	var exchangeRequest *TokenExchangeRequest
	if s.ExchangeRequest != nil {
		exchangeRequest = &TokenExchangeRequest{
			SubjectToken:       s.ExchangeRequest.SubjectToken,
			SubjectTokenType:   s.ExchangeRequest.SubjectTokenType,
			SubjectTokenInfo:   s.ExchangeRequest.SubjectTokenInfo,
			ActorToken:         s.ExchangeRequest.ActorToken,
			ActorTokenType:     s.ExchangeRequest.ActorTokenType,
			ActorTokenInfo:     s.ExchangeRequest.ActorTokenInfo,
			RequestedTokenType: s.ExchangeRequest.RequestedTokenType,
			Audience:           s.ExchangeRequest.Audience,
			Scopes:             s.ExchangeRequest.Scopes,
			Resource:           s.ExchangeRequest.Resource,
		}
	}

	return &TokenExchangeSession{
		ExchangeRequest: exchangeRequest,
		Subject:         s.Subject,
		Extra:           extra,
		ExpiresAt:       expiresAt,
	}
}
