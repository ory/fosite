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

package fosite

import (
	"context"
)

func (f *Fosite) NewDeviceAuthorizeResponse(ctx context.Context, dar DeviceAuthorizeRequester) (DeviceAuthorizeResponder, error) {
	var resp = NewDeviceAuthorizeResponse()

	for _, h := range f.DeviceAuthorizeEndpointHandlers {
		if err := h.HandleDeviceAuthorizeEndpointRequest(ctx, dar, resp); err != nil {
			return nil, err
		}
	}

	// if !dar.DidHandleAllResponseTypes() {
	// 	return nil, errorsx.WithStack(ErrUnsupportedResponseType)
	// }

	// if ar.GetDefaultResponseMode() == ResponseModeFragment && ar.GetResponseMode() == ResponseModeQuery {
	// 	return nil, ErrUnsupportedResponseMode.WithHintf("Insecure response_mode '%s' for the response_type '%s'.", ar.GetResponseMode(), ar.GetResponseTypes())
	// }

	return resp, nil
}