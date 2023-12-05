// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
)

type OpenIDConnectDeviceHandler struct {
	OpenIDConnectRequestStorage   OpenIDConnectRequestStorage
	OpenIDConnectRequestValidator *OpenIDConnectRequestValidator

	Config interface {
		fosite.IDTokenLifespanProvider
	}

	*IDTokenHandleHelper
}

func (c *OpenIDConnectDeviceHandler) HandleDeviceUserEndpointRequest(ctx context.Context, ar fosite.DeviceUserRequester, resp fosite.DeviceUserResponder) error {
	if !(ar.GetGrantedScopes().Has("openid")) {
		return nil
	}

	if !ar.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeDeviceCode)) {
		return nil
	}

	if len(ar.GetDeviceCodeSignature()) == 0 {
		return errorsx.WithStack(fosite.ErrMisconfiguration.WithDebug("The device code has not been issued yet, indicating a broken code configuration."))
	}

	if err := c.OpenIDConnectRequestValidator.ValidatePrompt(ctx, ar); err != nil {
		return err
	}

	if err := c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, ar.GetDeviceCodeSignature(), ar.Sanitize(oidcParameters)); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// there is no need to check for https, because it has already been checked by core.explicit

	return nil
}
