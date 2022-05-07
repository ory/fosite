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

func (f *Fosite) WriteAuthorizeError(ctx context.Context, rw http.ResponseWriter, ar AuthorizeRequester, err error) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	if f.ResponseModeHandler(ctx).ResponseModes().Has(ar.GetResponseMode()) {
		f.ResponseModeHandler(ctx).WriteAuthorizeError(ctx, rw, ar, err)
		return
	}

	rfcerr := ErrorToRFC6749Error(err).WithLegacyFormat(f.Config.GetUseLegacyErrorFormat(ctx)).WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx)).WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(ar))
	if !ar.IsRedirectURIValid() {
		rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

		js, err := json.Marshal(rfcerr)
		if err != nil {
			if f.Config.GetSendDebugMessagesToClients(ctx) {
				errorMessage := EscapeJSONString(err.Error())
				http.Error(rw, fmt.Sprintf(`{"error":"server_error","error_description":"%s"}`, errorMessage), http.StatusInternalServerError)
			} else {
				http.Error(rw, `{"error":"server_error"}`, http.StatusInternalServerError)
			}
			return
		}

		rw.WriteHeader(rfcerr.CodeField)
		_, _ = rw.Write(js)
		return
	}

	redirectURI := ar.GetRedirectURI()

	// The endpoint URI MUST NOT include a fragment component.
	redirectURI.Fragment = ""

	errors := rfcerr.ToValues()
	errors.Set("state", ar.GetState())

	var redirectURIString string
	if ar.GetResponseMode() == ResponseModeFormPost {
		rw.Header().Set("Content-Type", "text/html;charset=UTF-8")
		WriteAuthorizeFormPostResponse(redirectURI.String(), errors, GetPostFormHTMLTemplate(ctx, f), rw)
		return
	} else if ar.GetResponseMode() == ResponseModeFragment {
		redirectURIString = redirectURI.String() + "#" + errors.Encode()
	} else {
		for key, values := range redirectURI.Query() {
			for _, value := range values {
				errors.Add(key, value)
			}
		}
		redirectURI.RawQuery = errors.Encode()
		redirectURIString = redirectURI.String()
	}

	rw.Header().Set("Location", redirectURIString)
	rw.WriteHeader(http.StatusSeeOther)
}
