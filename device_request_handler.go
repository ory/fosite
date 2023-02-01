// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright © 2015-2021 Aeneas Rekkas <aeneas+oss@aeneas.io>
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
 * @copyright 	2015-2021 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package fosite

import (
	"context"
	"net/http"
	"strings"

	"github.com/ory/fosite/i18n"
	"github.com/ory/x/errorsx"
)

func (f *Fosite) NewDeviceRequest(ctx context.Context, req *http.Request) (DeviceRequester, error) {
	request := NewDeviceRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), req)

	if err := req.ParseForm(); err != nil {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebug(err.Error()))
	}
	request.Form = req.PostForm

	client, err := f.Store.GetClient(ctx, request.GetRequestForm().Get("client_id"))
	if err != nil {
		return nil, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 Client does not exist.").WithWrap(err).WithDebug(err.Error()))
	}
	request.Client = client

	if !client.GetGrantTypes().Has(string(GrantTypeDeviceCode)) {
		return nil, errorsx.WithStack(ErrInvalidGrant.WithHint("The requested OAuth 2.0 Client does not have the 'urn:ietf:params:oauth:grant-type:device_code' grant."))
	}

	if err := f.validateDeviceScope(ctx, req, request); err != nil {
		return nil, err
	}

	return request, nil
}

func (f *Fosite) validateDeviceScope(ctx context.Context, req *http.Request, request *DeviceRequest) error {
	scope := RemoveEmpty(strings.Split(request.Form.Get("scope"), " "))
	for _, permission := range scope {
		if !f.Config.GetScopeStrategy(ctx)(request.Client.GetScopes(), permission) {
			return errorsx.WithStack(ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", permission))
		}
	}
	request.SetRequestedScopes(scope)
	return nil
}
