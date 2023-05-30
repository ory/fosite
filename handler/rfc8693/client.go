// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import "github.com/ory/fosite"

type Client interface {
	// GetSupportedSubjectTokenTypes indicates the token types allowed for subject_token
	GetSupportedSubjectTokenTypes() []string
	// GetSupportedActorTokenTypes indicates the token types allowed for subject_token
	GetSupportedActorTokenTypes() []string
	// GetSupportedRequestTokenTypes indicates the token types allowed for requested_token_type
	GetSupportedRequestTokenTypes() []string
	// TokenExchangeAllowed checks if the subject token client allows the specified client
	// to perform the exchange
	TokenExchangeAllowed(client fosite.Client) bool
}
