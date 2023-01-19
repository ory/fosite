// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"

	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
)

var _ oauth2.CodeTokenEndpointHandler = (*DeviceAuthorizeHandler)(nil)

// DeviceAuthorizeHandler is a response handler for the Device UserCode introduced in the Device Authorize Grant
// as defined in https://www.rfc-editor.org/rfc/rfc8628
type DeviceAuthorizeHandler struct {
	DeviceStrategy DeviceCodeStrategy
	DeviceStorage  DeviceCodeStorage
}

func (c *DeviceAuthorizeHandler) ValidateGrantTypes(ctx context.Context, requester fosite.AccessRequester) error {
	if !requester.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeDeviceCode)) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:device_code\"."))
	}

	return nil
}

func (c *DeviceAuthorizeHandler) ValidateCode(ctx context.Context, request fosite.AccessRequester, code string) error {
	return c.DeviceStrategy.ValidateDeviceCode(ctx, request, code)
}

func (c *DeviceAuthorizeHandler) GetCodeAndSession(ctx context.Context, requester fosite.AccessRequester) (code string, signature string, request fosite.Requester, err error) {
	code = requester.GetRequestForm().Get("device_code")
	signature, err = c.DeviceStrategy.DeviceCodeSignature(ctx, code)
	if err != nil {
		return "", "", nil, errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	req, err := c.DeviceStorage.GetDeviceCodeSession(ctx, signature, requester.GetSession())
	return code, signature, req, err
}

func (c *DeviceAuthorizeHandler) InvalidateSession(ctx context.Context, signature string) error {
	return c.DeviceStorage.InvalidateDeviceCodeSession(ctx, signature)
}

// implement TokenEndpointHandler
func (c *DeviceAuthorizeHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeDeviceCode))
}

func (c *DeviceAuthorizeHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeDeviceCode))
}
