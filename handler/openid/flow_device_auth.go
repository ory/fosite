/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

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

func (c *OpenIDConnectDeviceHandler) HandleDeviceAuthorizeEndpointRequest(ctx context.Context, ar fosite.DeviceAuthorizeRequester, resp fosite.DeviceAuthorizeResponder) error {
	if !(ar.GetGrantedScopes().Has("openid")) {
		return nil
	}

	if !ar.GetClient().GetGrantTypes().Has("urn:ietf:params:oauth:grant-type:device_code") {
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
