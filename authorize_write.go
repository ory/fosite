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
	"fmt"
	"net/http"
	"regexp"
)

var (
	// scopeMatch = regexp.MustCompile("scope=[^\\&]+.*$")
	plusMatch = regexp.MustCompile("\\+")
)

var formPost = `
<html>
 <head><title>Submit</title></head>
 <body onload="javascript:document.forms[0].submit()">
  <form method="post" action="http://e334691c.ngrok.io/callback">
    <input type="hidden" name="state" value="%s"/>
	<input type="hidden" name="access_token" value="%s"/>
	<input type="hidden" name="id_token" value="%s"/>
  </form>
 </body>
</html>
`

func (f *Fosite) WriteAuthorizeResponse(rw http.ResponseWriter, ar AuthorizeRequester, resp AuthorizeResponder) {
	redir := ar.GetRedirectURI()

	// Explicit grants
	q := redir.Query()
	rq := resp.GetQuery()
	for k := range rq {
		q.Set(k, rq.Get(k))
	}
	redir.RawQuery = q.Encode()

	// Set custom headers, e.g. "X-MySuperCoolCustomHeader" or "X-DONT-CACHE-ME"...
	wh := rw.Header()
	rh := resp.GetHeader()
	for k := range rh {
		wh.Set(k, rh.Get(k))
	}

	// Implicit grants
	// The endpoint URI MUST NOT include a fragment component.
	redir.Fragment = ""

	u := redir.String()

	fr := resp.GetFragment()
	if len(fr) > 0 {
		u = u + "#" + fr.Encode()
	}

	u = plusMatch.ReplaceAllString(u, "%20")

	// https://tools.ietf.org/html/rfc6749#section-4.1.1
	// When a decision is established, the authorization server directs the
	// user-agent to the provided client redirection URI using an HTTP
	// redirection response, or by other means available to it via the
	// user-agent.
	wh.Set("Content-Type", "text/html; charset=utf-8")
	val, err := rw.Write([]byte(fmt.Sprintf(formPost, ar.GetState(), fr.Get("access_token"), fr.Get("id_token"))))
	fmt.Println(val, err)
	rw.WriteHeader(http.StatusOK)
}
