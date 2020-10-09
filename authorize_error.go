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
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

func (f *Fosite) WriteAuthorizeError(rw http.ResponseWriter, ar AuthorizeRequester, err error) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	rfcerr := ErrorToRFC6749Error(err)
	if !f.SendDebugMessagesToClients {
		rfcerr = rfcerr.Sanitize()
	}

	if !ar.IsRedirectURIValid() {
		rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

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

		rw.WriteHeader(rfcerr.Code)
		_, _ = rw.Write(js)
		return
	}

	redirectURI := ar.GetRedirectURI()

	// The endpoint URI MUST NOT include a fragment component.
	redirectURI.Fragment = ""

	query := rfcerr.ToValues()
	query.Add("state", ar.GetState())

	var redirectURIString string
	if ar.GetRequestForm().Get("response_mode") == "form_post" {
		rw.Header().Add("Content-Type", "text/html;charset=UTF-8")
		WriteAuthorizeFormPostResponse(redirectURI.String(), query, rw)
		return
	} else if !(len(ar.GetResponseTypes()) == 0 || ar.GetResponseTypes().ExactOne("code")) && !errors.Is(err, ErrUnsupportedResponseType) {
		redirectURIString = redirectURI.String() + "#" + query.Encode()
	} else {
		for key, values := range redirectURI.Query() {
			for _, value := range values {
				query.Add(key, value)
			}
		}
		redirectURI.RawQuery = query.Encode()
		redirectURIString = redirectURI.String()
	}

	rw.Header().Add("Location", redirectURIString)
	rw.WriteHeader(http.StatusFound)
}
