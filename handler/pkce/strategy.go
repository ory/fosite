// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"regexp"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
)

// CodeVerifierStrategy validates a PKCE code_verifier: first its format,
// independent of any code_challenge, and then its match against a bound
// code_challenge. Handler defaults to DefaultCodeVerifierStrategy, which
// enforces RFC 7636's length, character-set, and comparison rules.
//
// Provide a custom CodeVerifierStrategy to interoperate with authorization
// servers that predate or relax those rules -- for example, when migrating
// clients from a legacy provider that never enforced the RFC 7636 minimum
// verifier length. Overriding this strategy still goes through Handler's own
// session lifecycle and EnforcePKCE / EnforcePKCEForPublicClients handling; only
// the verifier's format and comparison rules change.
type CodeVerifierStrategy interface {
	// ValidateVerifierFormat validates the code_verifier's length and character
	// set. It is called before ValidateChallenge, and independent of it: a
	// request with no registered code_challenge never reaches ValidateChallenge,
	// but its verifier's format is still checked here.
	ValidateVerifierFormat(ctx context.Context, verifier string) error

	// ValidateChallenge compares verifier against challenge using method. It
	// returns an error if they do not match, or if method is not supported.
	ValidateChallenge(ctx context.Context, method, challenge, verifier string) error
}

// DefaultCodeVerifierStrategy implements CodeVerifierStrategy per RFC 7636
// section 4.1 (verifier format) and section 4.6 (challenge verification).
type DefaultCodeVerifierStrategy struct{}

var verifierWrongFormat = regexp.MustCompile("[^\\w\\.\\-~]")

// ValidateVerifierFormat implements CodeVerifierStrategy.
//
// NOTE: The code verifier SHOULD have enough entropy to make it impractical to
// guess the value. It is RECOMMENDED that the output of a suitable random
// number generator be used to create a 32-octet sequence. The octet sequence is
// then base64url-encoded to produce a 43-octet URL safe string to use as the
// code verifier.
func (DefaultCodeVerifierStrategy) ValidateVerifierFormat(_ context.Context, verifier string) error {
	nv := len(verifier)

	switch {
	case nv < 43:
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("The PKCE code verifier must be at least 43 characters."))
	case nv > 128:
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("The PKCE code verifier can not be longer than 128 characters."))
	case verifierWrongFormat.MatchString(verifier):
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("The PKCE code verifier must only contain [a-Z], [0-9], '-', '.', '_', '~'."))
	}

	return nil
}

// ValidateChallenge implements CodeVerifierStrategy.
//
// Upon receipt of the request at the token endpoint, the server verifies it by
// calculating the code challenge from the received "code_verifier" and
// comparing it with the previously associated "code_challenge", after first
// transforming it according to the "code_challenge_method" method specified by
// the client.
//
//	If the "code_challenge_method" from Section 4.3 was "S256", the
//
// received "code_verifier" is hashed by SHA-256, base64url-encoded, and
// then compared to the "code_challenge", i.e.:
//
// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
//
// If the "code_challenge_method" from Section 4.3 was "plain", they are
// compared directly, i.e.:
//
// code_verifier == code_challenge.
//
//	If the values are equal, the token endpoint MUST continue processing
//
// as normal (as defined by OAuth 2.0 [RFC6749]). If the values are not
// equal, an error response indicating "invalid_grant" as described in
// Section 5.2 of [RFC6749] MUST be returned.
func (DefaultCodeVerifierStrategy) ValidateChallenge(_ context.Context, method, challenge, verifier string) error {
	switch method {
	case "S256":
		hash := sha256.New()
		if _, err := hash.Write([]byte(verifier)); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}

		if base64.RawURLEncoding.EncodeToString(hash.Sum([]byte{})) != challenge {
			return errorsx.WithStack(fosite.ErrInvalidGrant.
				WithHint("The PKCE code challenge did not match the code verifier."))
		}
	case "plain":
		fallthrough
	default:
		if verifier != challenge {
			return errorsx.WithStack(fosite.ErrInvalidGrant.
				WithHint("The PKCE code challenge did not match the code verifier."))
		}
	}

	return nil
}
