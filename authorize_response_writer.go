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
	"net/http"
	"net/url"

	"github.com/ory/x/errorsx"
)

func (f *Fosite) NewAuthorizeResponse(ctx context.Context, ar AuthorizeRequester, session Session) (AuthorizeResponder, error) {
	var resp = &AuthorizeResponse{
		Header:     http.Header{},
		Parameters: url.Values{},
	}

	ctx = context.WithValue(ctx, AuthorizeRequestContextKey, ar)
	ctx = context.WithValue(ctx, AuthorizeResponseContextKey, resp)

	ar.SetSession(session)
	for _, h := range f.Config.GetAuthorizeEndpointHandlers(ctx) {
		if err := h.HandleAuthorizeEndpointRequest(ctx, ar, resp); err != nil {
			return nil, err
		}
	}

	if !ar.DidHandleAllResponseTypes() {
		return nil, errorsx.WithStack(ErrUnsupportedResponseType)
	}

	if ar.GetDefaultResponseMode() == ResponseModeFragment && ar.GetResponseMode() == ResponseModeQuery {
		return nil, ErrUnsupportedResponseMode.WithHintf("Insecure response_mode '%s' for the response_type '%s'.", ar.GetResponseMode(), ar.GetResponseTypes())
	}

	return resp, nil
}
