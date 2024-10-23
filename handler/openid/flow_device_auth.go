// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"

	"github.com/ory/fosite/handler/rfc8628"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

// OpenIDConnectDeviceHandler a response handler for the Device Authorization Grant with OpenID Connect identity layer
type OpenIDConnectDeviceHandler struct {
	OpenIDConnectRequestStorage OpenIDConnectRequestStorage
	DeviceCodeStrategy          rfc8628.DeviceCodeStrategy

	Config interface {
		fosite.IDTokenLifespanProvider
	}

	*IDTokenHandleHelper
}

func (c *OpenIDConnectDeviceHandler) HandleDeviceEndpointRequest(ctx context.Context, dar fosite.DeviceRequester, resp fosite.DeviceResponder) error {
	if !(dar.GetRequestedScopes().Has("openid")) {
		return nil
	}

	if !dar.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeDeviceCode)) {
		return nil
	}

	if resp.GetDeviceCode() == "" {
		return errorsx.WithStack(fosite.ErrMisconfiguration.WithDebug("The device code has not been issued yet, indicating a broken code configuration."))
	}

	signature, err := c.DeviceCodeStrategy.DeviceCodeSignature(ctx, resp.GetDeviceCode())
	if err != nil {
		return err
	}

	if err := c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, signature, dar.Sanitize(oidcParameters)); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}
