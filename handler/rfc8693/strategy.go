// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

//go:generate mockgen -source=strategy.go -destination=../../internal/oauth2_token_exchange_strategy.go -package=internal

import "github.com/ory/fosite"

type ClientAuthenticationStrategy interface {
	CanSkipClientAuth(requester fosite.AccessRequester) bool
}

// DefaultClientAuthenticationStrategy enforces client authentication for all the cases.
type DefaultClientAuthenticationStrategy struct{}

func (s *DefaultClientAuthenticationStrategy) CanSkipClientAuth(requester fosite.Requester) bool {
	return false
}
