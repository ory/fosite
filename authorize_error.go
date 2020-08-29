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
	"net/http"
	"net/url"

	"github.com/pkg/errors"
)

func (f *Fosite) WriteAuthorizeError(rw http.ResponseWriter, ar AuthorizeRequester, err error) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	rfcerr := ErrorToRFC6749Error(err)
	if !ar.IsRedirectURIValid() {
		if !f.SendDebugMessagesToClients {
			rfcerr.Debug = ""
		}

		js, err := json.MarshalIndent(rfcerr, "", "\t")
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		rw.Header().Set("Content-Type", "application/json;charset=UTF-8")
		rw.WriteHeader(rfcerr.Code)
		rw.Write(js)
		return
	}

	redirectURI := ar.GetRedirectURI()
	error_description := rfcerr.Description
	query := url.Values{}
	query.Add("error", rfcerr.Name)
	query.Add("state", ar.GetState())
	// We expose both error hint and debug strings through standard error description, too
	// (they are non-standard fields and some clients do not show them).
	if rfcerr.Hint != "" {
		query.Add("error_hint", rfcerr.Hint)
		error_description += ": " + rfcerr.Hint
	}
	if f.SendDebugMessagesToClients && rfcerr.Debug != "" {
		query.Add("error_debug", rfcerr.Debug)
		error_description += " (" + rfcerr.Debug + ")"
	}
	query.Add("error_description", error_description)

	if !(len(ar.GetResponseTypes()) == 0 || ar.GetResponseTypes().ExactOne("code")) && errors.Cause(err) != ErrUnsupportedResponseType {
		redirectURI.Fragment = query.Encode()
	} else {
		for key, values := range redirectURI.Query() {
			for _, value := range values {
				query.Add(key, value)
			}
		}
		redirectURI.RawQuery = query.Encode()
	}

	rw.Header().Add("Location", redirectURI.String())
	rw.WriteHeader(http.StatusFound)
}
