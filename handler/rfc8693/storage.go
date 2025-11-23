// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
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
