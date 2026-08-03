// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc9396

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

var _ fosite.TokenEndpointHandler = (*TokenRequestHandler)(nil)

type TokenRequestHandler struct {
	Config fosite.RFC9396ConfigProvider
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.1.3 (everything) and
// https://tools.ietf.org/html/rfc7523#section-2.1 (everything)
func (h *TokenRequestHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	if !h.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	// check requester type
	req, ok := requester.(fosite.RFC9396Requester)
	if !ok {
		return nil
	}

	return validateAndEnrichRequester(ctx, requester.GetClient(), req, h.Config, requester.GetRequestForm().Get("authorization_details"))
}

func (h *TokenRequestHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	return nil
}

func (h *TokenRequestHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	// different handlers manage the client auth requirement
	return true
}

func (h *TokenRequestHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// this handler is for all direct token calls.
	return requester.GetGrantTypes().HasOneOf(
		string(fosite.GrantTypeClientCredentials),
		string(fosite.GrantTypeJWTBearer),
		string(fosite.GrantTypePassword),
		string(fosite.GrantTypeTokenExchange),
		string(fosite.GrantTypePreAuthorizeCode),
		string(fosite.GrantTypeRefreshToken))
}
