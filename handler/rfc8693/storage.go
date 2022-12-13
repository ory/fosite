// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

//go:generate mockgen -source=storage.go -destination=../../internal/oauth2_token_exchange_storage.go -package=internal

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

// RFC8693Storage hold information needed to perform token exchange.
type RFC8693Storage interface {
	// GetAllowedClientIDs returns clientIDs that can be used for subject_token.
	// The subject token is a security token that represents the identity of
	// the party on behalf of whom the request is being made.
	// https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
	GetAllowedClientIDs(ctx context.Context, clientID string) ([]string, error)

	// GetIDTokenPublicKey returns the public key that can be used to verify ID Token.
	GetIDTokenPublicKey(ctx context.Context, iss, kid string) (interface{}, error)

	// GetImpersonateSubject returns subject value to use the token based on a JWT.
	GetImpersonateSubject(ctx context.Context, claims jwt.MapClaims, req fosite.Requester) (string, error)
}
