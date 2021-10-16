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
	"encoding/json"
	"fmt"
	"net/http"
)

func (f *Fosite) NewPushedAuthorizeResponse(ctx context.Context, ar AuthorizeRequester, session Session) (PushedAuthorizeResponder, error) {
	var resp = &PushedAuthorizeResponse{
		Header: http.Header{},
		Extra:  map[string]interface{}{},
	}

	ctx = context.WithValue(ctx, AuthorizeRequestContextKey, ar)
	ctx = context.WithValue(ctx, PushedAuthorizeResponseContextKey, resp)

	ar.SetSession(session)
	for _, h := range f.PushedAuthorizeEndpointHandlers {
		if err := h.HandlePushedAuthorizeEndpointRequest(ctx, ar, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func (f *Fosite) WritePushedAuthorizeResponse(rw http.ResponseWriter, ar AuthorizeRequester, resp PushedAuthorizeResponder) {
	// Set custom headers, e.g. "X-MySuperCoolCustomHeader" or "X-DONT-CACHE-ME"...
	wh := rw.Header()
	rh := resp.GetHeader()
	for k := range rh {
		wh.Set(k, rh.Get(k))
	}

	wh.Set("Cache-Control", "no-store")
	wh.Set("Pragma", "no-cache")
	wh.Set("Content-Type", "application/json;charset=UTF-8")

	js, err := json.Marshal(resp.ToMap())
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write(js)
}

func (f *Fosite) WritePushedAuthorizeError(rw http.ResponseWriter, ar AuthorizeRequester, err error) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")
	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

	rfcerr := ErrorToRFC6749Error(err).WithLegacyFormat(f.UseLegacyErrorFormat).WithExposeDebug(f.SendDebugMessagesToClients)

	js, err := json.Marshal(rfcerr)
	if err != nil {
		if f.SendDebugMessagesToClients {
			errorMessage := EscapeJSONString(err.Error())
			http.Error(rw, fmt.Sprintf(`{"error":"server_error","error_description":"%s"}`, errorMessage), http.StatusInternalServerError)
		} else {
			http.Error(rw, `{"error":"server_error"}`, http.StatusInternalServerError)
		}
		return
	}

	rw.WriteHeader(rfcerr.CodeField)
	_, _ = rw.Write(js)
}
