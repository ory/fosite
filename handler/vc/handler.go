// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package vc

import (
	"context"

	"github.com/ory/fosite/handler/oauth2"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

const (
	draftScope         = "userinfo_credential_draft_00"
	draftNonceField    = "c_nonce_draft_00"
	draftNonceExpField = "c_nonce_expires_in_draft_00"
)

type Handler struct {
	Config interface {
		fosite.AccessTokenLifespanProvider
		fosite.TokenURLProvider
		fosite.GrantTypeJWTBearerCanSkipClientAuthProvider
		fosite.GrantTypeJWTBearerIDOptionalProvider
		fosite.GrantTypeJWTBearerIssuedDateOptionalProvider
		fosite.GetJWTMaxDurationProvider
		fosite.AudienceStrategyProvider
		fosite.ScopeStrategyProvider
	}

	*oauth2.HandleHelper
}

var _ fosite.TokenEndpointHandler = (*Handler)(nil)

func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	if !request.GetGrantedScopes().Has("openid") {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	return nil
}

func (c *Handler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	response.SetExtra(draftNonceField, "random nonce")
	response.SetExtra(draftNonceExpField, "random nonce expiry")

	return nil
}

func (c *Handler) CanSkipClientAuth(context.Context, fosite.AccessRequester) bool {
	return false
}

func (c *Handler) CanHandleTokenEndpointRequest(_ context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantedScopes().Has(draftScope)
}
