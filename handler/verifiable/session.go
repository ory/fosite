// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package verifiable

import "time"

type Session interface {

	// In the context of credential issuance with grant_type 'authorization_code'
	// There is parameter 'issuer_state' to bind the authorization request with a Credential Issuer context

	// GetIssuerState retrieve 'issuer_state' from the session
	GetIssuerState() string

	// SetIssuerState associates 'issuer_state' with the session
	SetIssuerState(state string)

	// CredentialNonceHandler will generate 'c_nonce' and associated it with token's session
	// During introspection of the token, information about the nonce can be returned
	// This model allows for decoupling between Credential Issuer and Authorization Server.

	// GetCredentialNonce returns the 'c_nonce' associated with the session and the expiredAt
	GetCredentialNonce() (string, time.Time)

	// SetCredentialNonce associates the 'c_nonce' with the session
	SetCredentialNonce(c_nonce string, expiresAt time.Time)
}
