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
)

// Once the user has approved the grant he will be redirected on his loggin machine
// to a webpage (usally hosted in hydra-ui) to understand that he was connected successfully
// and that he can close this tab and return to his non-interactive device;
func (f *Fosite) WriteDeviceAuthorizeResponse(ctx context.Context, r *http.Request, rw http.ResponseWriter, requester DeviceAuthorizeRequester, responder DeviceAuthorizeResponder) {
	http.Redirect(rw, r, f.Config.GetDeviceDone(ctx), http.StatusSeeOther)
}
