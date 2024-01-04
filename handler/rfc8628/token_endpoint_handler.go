// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"

	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
)

// DeviceHandler is a token response handler for the Device Code introduced in the Device Authorize Grant
// as defined in https://www.rfc-editor.org/rfc/rfc8628
type DeviceHandler struct {
	DeviceRateLimitStrategy DeviceRateLimitStrategy
	DeviceStrategy          DeviceCodeStrategy
	DeviceStorage           DeviceCodeStorage
}

type DeviceCodeTokenEndpointHandler struct {
	oauth2.GenericCodeTokenEndpointHandler
}

var _ oauth2.CodeTokenEndpointHandler = (*DeviceHandler)(nil)
var _ fosite.TokenEndpointHandler = (*DeviceCodeTokenEndpointHandler)(nil)

func (c *DeviceHandler) ValidateGrantTypes(ctx context.Context, requester fosite.AccessRequester) error {
	if !requester.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeDeviceCode)) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:device_code\"."))
	}

	return nil
}

func (c *DeviceHandler) ValidateCode(ctx context.Context, request fosite.AccessRequester, code string) error {
	return c.DeviceStrategy.ValidateDeviceCode(ctx, request, code)
}

func (c *DeviceHandler) GetCodeAndSession(ctx context.Context, requester fosite.AccessRequester) (code string, signature string, request fosite.Requester, err error) {
	code = requester.GetRequestForm().Get("device_code")

	if c.DeviceRateLimitStrategy.ShouldRateLimit(ctx, code) {
		return "", "", nil, fosite.ErrPollingRateLimited
	}

	signature, err = c.DeviceStrategy.DeviceCodeSignature(ctx, code)
	if err != nil {
		return "", "", nil, errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	req, err := c.DeviceStorage.GetDeviceCodeSession(ctx, signature, requester.GetSession())
	return code, signature, req, err
}

func (c *DeviceHandler) InvalidateSession(ctx context.Context, signature string) error {
	return c.DeviceStorage.InvalidateDeviceCodeSession(ctx, signature)
}

// implement TokenEndpointHandler
func (c *DeviceHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeDeviceCode))
}

func (c *DeviceHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeDeviceCode))
}
