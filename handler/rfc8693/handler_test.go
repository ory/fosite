// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ory/fosite"
)

func TestHandler_CanHandleTokenEndpointRequest(t *testing.T) {
	config := &fosite.Config{}
	handler := &Handler{
		Config: config,
	}

	testCases := []struct {
		name         string
		grantTypes   []string
		shouldHandle bool
	}{
		{
			name:         "should handle token exchange grant",
			grantTypes:   []string{GrantTypeTokenExchange},
			shouldHandle: true,
		},
		{
			name:         "should not handle authorization code grant",
			grantTypes:   []string{"authorization_code"},
			shouldHandle: false,
		},
		{
			name:         "should not handle client credentials grant",
			grantTypes:   []string{"client_credentials"},
			shouldHandle: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := &fosite.AccessRequest{
				GrantTypes: fosite.Arguments(tc.grantTypes),
			}

			result := handler.CanHandleTokenEndpointRequest(context.Background(), request)
			assert.Equal(t, tc.shouldHandle, result)
		})
	}
}

func TestHandler_CanSkipClientAuth(t *testing.T) {
	config := &fosite.Config{}
	handler := &Handler{
		Config: config,
	}

	request := &fosite.AccessRequest{}

	// Token exchange should never skip client authentication
	result := handler.CanSkipClientAuth(context.Background(), request)
	assert.False(t, result)
}

func TestTokenExchangeSession_Clone(t *testing.T) {
	original := &TokenExchangeSession{
		ExchangeRequest: &TokenExchangeRequest{
			SubjectToken:     "token",
			SubjectTokenType: TokenTypeAccessToken,
			Scopes:           fosite.Arguments{"read"},
		},
		Subject: "user123",
		Extra: map[string]interface{}{
			"key": "value",
		},
	}

	cloned := original.Clone().(*TokenExchangeSession)

	assert.Equal(t, original.Subject, cloned.Subject)
	assert.Equal(t, original.ExchangeRequest.SubjectToken, cloned.ExchangeRequest.SubjectToken)
	assert.Equal(t, original.Extra["key"], cloned.Extra["key"])

	// Verify it's a deep copy
	cloned.Subject = "different"
	assert.NotEqual(t, original.Subject, cloned.Subject)

	cloned.Extra["key"] = "different"
	assert.NotEqual(t, original.Extra["key"], cloned.Extra["key"])
}

func TestHandler_isValidTokenType(t *testing.T) {
	config := &fosite.Config{
		TokenExchangeTokenTypes: []string{
			TokenTypeAccessToken,
			TokenTypeRefreshToken,
		},
	}

	handler := &Handler{
		Config: config,
	}

	testCases := []struct {
		name      string
		tokenType string
		isValid   bool
	}{
		{
			name:      "should accept access token type",
			tokenType: TokenTypeAccessToken,
			isValid:   true,
		},
		{
			name:      "should accept refresh token type",
			tokenType: TokenTypeRefreshToken,
			isValid:   true,
		},
		{
			name:      "should reject unsupported token type",
			tokenType: "unsupported_type",
			isValid:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := handler.isValidTokenType(context.Background(), tc.tokenType)
			assert.Equal(t, tc.isValid, result)
		})
	}
}
