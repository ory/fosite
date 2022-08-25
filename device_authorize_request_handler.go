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
 * @author		Luke Stoward
 * @copyright 	2015-2021 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

 package fosite

 import (
	 "context"
	 "net/http"
	 "strings"
 
	 "github.com/ory/x/errorsx"
 )
 
 func (f *Fosite) NewDeviceAuthorizeRequest(ctx context.Context, r *http.Request) (DeviceAuthorizeRequester, error) {
	 request := NewDeviceAuthorizeRequest()
 
	 if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		 return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebug(err.Error()))
	 }
	 request.Form = r.Form
 
	 client, err := f.Store.GetClient(ctx, request.GetRequestForm().Get("client_id"))
	 if err != nil {
		 return request, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 Client does not exist.").WithWrap(err).WithDebug(err.Error()))
	 }
	 request.Client = client
 
	 if err := f.validateDeviceAuthorizeScope(r, request); err != nil {
		 return request, err
	 }
 
	 return request, nil
 }
 
 func (f *Fosite) AuthorizeDeviceCode(ctx context.Context, deviceCode string, requester Requester) error {
 
	 for _, h := range f.DeviceAuthorizeEndpointHandlers {
		 if err := h.AuthorizeDeviceCode(ctx, deviceCode, requester); err != nil {
			 return err
		 }
	 }
	 return nil
 }
 
 // validateDeviceAuthorizeScope checks that the requested scopes are allowed for the client
 func (f *Fosite) validateDeviceAuthorizeScope(_ *http.Request, request *DeviceAuthorizeRequest) error {
	 scope := RemoveEmpty(strings.Split(request.Form.Get("scope"), " "))
	 for _, permission := range scope {
		 if !f.ScopeStrategy(request.Client.GetScopes(), permission) {
			 return errorsx.WithStack(ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", permission))
		 }
	 }
	 request.SetRequestedScopes(scope)
 
	 return nil
 }