// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"strings"

	"github.com/ory/x/errorsx"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
)

func (c *OpenIDConnectDeviceHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	return errorsx.WithStack(fosite.ErrUnknownRequest)
}

func (OpenIDConnectDeviceHandler) getDeviceCodeSignature(token string) string {
	split := strings.Split(token, ".")

	if len(split) != 2 {
		return ""
	}

	return split[1]
}

func (c *OpenIDConnectDeviceHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	deviceCodeSignature := c.getDeviceCodeSignature(requester.GetRequestForm().Get("device_code"))
	authorize, err := c.OpenIDConnectRequestStorage.GetOpenIDConnectSession(ctx, deviceCodeSignature, requester)
	if errors.Is(err, ErrNoSessionFound) {
		return errorsx.WithStack(fosite.ErrUnknownRequest.WithWrap(err).WithDebug(err.Error()))
	} else if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if !authorize.GetGrantedScopes().Has("openid") {
		return errorsx.WithStack(fosite.ErrMisconfiguration.WithDebug("An OpenID Connect session was found but the openid scope is missing, probably due to a broken code configuration."))
	}

	if !requester.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeDeviceCode)) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant \"urn:ietf:params:oauth:grant-type:device_code\"."))
	}

	sess, ok := authorize.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to generate id token because session must be of type fosite/handler/openid.Session."))
	}

	claims := sess.IDTokenClaims()
	if claims.Subject == "" {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to generate id token because subject is an empty string."))
	}

	claims.AccessTokenHash = c.GetAccessTokenHash(ctx, requester, responder)

	// The response type `id_token` is only required when performing the implicit or hybrid flow, see:
	// https://openid.net/specs/openid-connect-registration-1_0.html
	//
	// if !requester.GetClient().GetResponseTypes().Has("id_token") {
	// 	return errorsx.WithStack(fosite.ErrInvalidGrant.WithDebug("The client is not allowed to use response type id_token"))
	// }

	idTokenLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.IDToken, c.Config.GetIDTokenLifespan(ctx))
	return c.IssueExplicitIDToken(ctx, idTokenLifespan, authorize, responder)
}

func (c *OpenIDConnectDeviceHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

func (c *OpenIDConnectDeviceHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeDeviceCode))
}
