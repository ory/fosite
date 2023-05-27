// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

type Client interface {
	// GetSupportedSubjectTokenTypes indicates the token types allowed for subject_token
	GetSupportedSubjectTokenTypes() []string
	// GetSupportedActorTokenTypes indicates the token types allowed for subject_token
	GetSupportedActorTokenTypes() []string
	// GetSupportedRequestTokenTypes indicates the token types allowed for requested_token_type
	GetSupportedRequestTokenTypes() []string
	// GetAllowedClientIDsForTokenExchange indicates the clients that are allowed to
	// exchange the subject token for an impersonated or delegated token.
	GetAllowedClientIDsForTokenExchange() []string
}
