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
	"net/http"
)

func (f *Fosite) WriteAuthorizeResponse(rw http.ResponseWriter, ar AuthorizeRequester, resp AuthorizeResponder) {
	// Set custom headers, e.g. "X-MySuperCoolCustomHeader" or "X-DONT-CACHE-ME"...
	wh := rw.Header()
	rh := resp.GetHeader()
	for k := range rh {
		wh.Set(k, rh.Get(k))
	}

	wh.Set("Cache-Control", "no-store")
	wh.Set("Pragma", "no-cache")

	redir := ar.GetRedirectURI()
	switch rm := ar.GetResponseMode(); rm {
	case ResponseModeFormPost:
		//form_post
		rw.Header().Add("Content-Type", "text/html;charset=UTF-8")
		WriteAuthorizeFormPostResponse(redir.String(), resp.GetParameters(), GetPostFormHTMLTemplate(*f), rw)
		return
	case ResponseModeQuery, ResponseModeDefault:
		// Explicit grants
		q := redir.Query()
		rq := resp.GetParameters()
		for k := range rq {
			q.Set(k, rq.Get(k))
		}
		redir.RawQuery = q.Encode()
		sendRedirect(redir.String(), rw)
		return
	case ResponseModeFragment:
		// Implicit grants
		// The endpoint URI MUST NOT include a fragment component.
		redir.Fragment = ""

		u := redir.String()
		fr := resp.GetParameters()
		if len(fr) > 0 {
			u = u + "#" + fr.Encode()
		}
		sendRedirect(u, rw)
		return
	default:
		if f.ResponseModeHandler().ResponseModes().Has(rm) {
			f.ResponseModeHandler().WriteAuthorizeResponse(rw, ar, resp)
			return
		}
	}
}

// https://tools.ietf.org/html/rfc6749#section-4.1.1
// When a decision is established, the authorization server directs the
// user-agent to the provided client redirection URI using an HTTP
// redirection response, or by other means available to it via the
// user-agent.
func sendRedirect(url string, rw http.ResponseWriter) {
	rw.Header().Set("Location", url)
	rw.WriteHeader(http.StatusSeeOther)
}
