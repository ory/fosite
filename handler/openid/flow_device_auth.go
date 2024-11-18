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
	// We don't want to create the openid session on this call, because we don't know if the user
	// will actually complete the flow and give consent. The implementer MUST call the CreateOpenIDConnectSession
	// methods when the user logs in to instantiate the session.
	if !(dar.GetRequestedScopes().Has("openid")) {
		return nil
	}

	if !dar.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeDeviceCode)) {
		return nil
	}

	if resp.GetDeviceCode() == "" {
		return errorsx.WithStack(fosite.ErrMisconfiguration.WithDebug("The device code has not been issued yet, indicating a broken code configuration."))
	}

	return nil
}
