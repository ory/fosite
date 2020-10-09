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

package fosite_test

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	. "github.com/ory/fosite"
	. "github.com/ory/fosite/internal"
)

// Test for
// * https://tools.ietf.org/html/rfc6749#section-4.1.2.1
//   If the request fails due to a missing, invalid, or mismatching
//   redirection URI, or if the client identifier is missing or invalid,
//   the authorization server SHOULD inform the resource owner of the
//   error and MUST NOT automatically redirect the user-agent to the
//   invalid redirection URI.
// * https://tools.ietf.org/html/rfc6749#section-3.1.2
//   The redirection endpoint URI MUST be an absolute URI as defined by
//   [RFC3986] Section 4.3.  The endpoint URI MAY include an
//   "application/x-www-form-urlencoded" formatted (per Appendix B) query
//   component ([RFC3986] Section 3.4), which MUST be retained when adding
//   additional query parameters.  The endpoint URI MUST NOT include a
//   fragment component.
func TestWriteAuthorizeError(t *testing.T) {
	var urls = []string{
		"https://foobar.com/",
		"https://foobar.com/?foo=bar",
	}
	var purls = []*url.URL{}
	for _, u := range urls {
		purl, _ := url.Parse(u)
		purls = append(purls, purl)
	}

	header := http.Header{}
	for k, c := range []struct {
		err         error
		debug       bool
		mock        func(*MockResponseWriter, *MockAuthorizeRequester)
		checkHeader func(*testing.T, int)
	}{
		{
			err: ErrInvalidGrant,
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(false)
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusBadRequest)
				rw.EXPECT().Write(gomock.Any())
			},
			checkHeader: func(t *testing.T, k int) {
				assert.Equal(t, "application/json;charset=UTF-8", header.Get("Content-Type"))
				assert.Equal(t, "no-store", header.Get("Cache-Control"))
				assert.Equal(t, "no-cache", header.Get("Pragma"))
			},
		},
		{
			debug: true,
			err:   ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[0]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().MaxTimes(2).Return(Arguments([]string{"code"}))
				req.EXPECT().GetRequestForm().Return(url.Values{})
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?error=invalid_request&error_debug=with-debug&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed%0A%0AMake+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.%0A%0Awith-debug&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get("Location"))
				assert.Equal(t, a, b)
				assert.Equal(t, "no-store", header.Get("Cache-Control"))
				assert.Equal(t, "no-cache", header.Get("Pragma"))
			},
		},
		{
			err: ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[0]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().MaxTimes(2).Return(Arguments([]string{"code"}))
				req.EXPECT().GetRequestForm().Return(url.Values{})
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed%0A%0AMake+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get("Location"))
				assert.Equal(t, a, b)
				assert.Equal(t, "no-store", header.Get("Cache-Control"))
				assert.Equal(t, "no-cache", header.Get("Pragma"))
			},
		},
		{
			err: ErrInvalidRequest,
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().MaxTimes(2).Return(Arguments([]string{"code"}))
				req.EXPECT().GetRequestForm().Return(url.Values{})
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed%0A%0AMake+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&foo=bar&state=foostate")
				b, _ := url.Parse(header.Get("Location"))
				assert.Equal(t, a, b)
				assert.Equal(t, "no-store", header.Get("Cache-Control"))
				assert.Equal(t, "no-cache", header.Get("Pragma"))
			},
		},
		{
			err: ErrUnsupportedGrantType,
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().MaxTimes(2).Return(Arguments([]string{"foobar"}))
				req.EXPECT().GetRequestForm().Return(url.Values{})
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?foo=bar#error=unsupported_grant_type&error_description=The+authorization+grant+type+is+not+supported+by+the+authorization+server&state=foostate")
				b, _ := url.Parse(header.Get("Location"))
				assert.Equal(t, a, b)
				assert.Equal(t, "no-store", header.Get("Cache-Control"))
				assert.Equal(t, "no-cache", header.Get("Pragma"))
			},
		},
		{
			err: ErrInvalidRequest,
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[0]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().MaxTimes(2).Return(Arguments([]string{"token"}))
				req.EXPECT().GetRequestForm().Return(url.Values{})
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/#error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed%0A%0AMake+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get("Location"))
				assert.Equal(t, a, b)
				assert.Equal(t, "no-store", header.Get("Cache-Control"))
				assert.Equal(t, "no-cache", header.Get("Pragma"))
			},
		},
		{
			err: ErrInvalidRequest,
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().MaxTimes(2).Return(Arguments([]string{"token"}))
				req.EXPECT().GetRequestForm().Return(url.Values{})
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?foo=bar#error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed%0A%0AMake+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get("Location"))
				assert.Equal(t, a, b)
				assert.Equal(t, "no-store", header.Get("Cache-Control"))
				assert.Equal(t, "no-cache", header.Get("Pragma"))
			},
		},
		{
			err: ErrInvalidRequest,
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[0]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().MaxTimes(2).Return(Arguments([]string{"code", "token"}))
				req.EXPECT().GetRequestForm().Return(url.Values{})
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/#error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed%0A%0AMake+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get("Location"))
				assert.Equal(t, a, b)
				assert.Equal(t, "no-store", header.Get("Cache-Control"))
				assert.Equal(t, "no-cache", header.Get("Pragma"))
			},
		},
		{
			err: ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().MaxTimes(2).Return(Arguments([]string{"code", "token"}))
				req.EXPECT().GetRequestForm().Return(url.Values{})
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?foo=bar#error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed%0A%0AMake+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get("Location"))
				assert.Equal(t, a, b)
				assert.Equal(t, "no-store", header.Get("Cache-Control"))
				assert.Equal(t, "no-cache", header.Get("Pragma"))
			},
		},
		{
			debug: true,
			err:   ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().MaxTimes(2).Return(Arguments([]string{"code", "token"}))
				req.EXPECT().GetRequestForm().Return(url.Values{})
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?foo=bar#error=invalid_request&error_debug=with-debug&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed%0A%0AMake+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.%0A%0Awith-debug&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get("Location"))
				assert.Equal(t, a, b)
				assert.Equal(t, "no-store", header.Get("Cache-Control"))
				assert.Equal(t, "no-cache", header.Get("Pragma"))
			},
		},
		{
			debug: true,
			err:   ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().MaxTimes(2).Return(Arguments([]string{"id_token"}))
				req.EXPECT().GetRequestForm().Return(url.Values{})
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?foo=bar#error=invalid_request&error_debug=with-debug&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed%0A%0AMake+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.%0A%0Awith-debug&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get("Location"))
				assert.Equal(t, a, b)
				assert.Equal(t, "no-store", header.Get("Cache-Control"))
				assert.Equal(t, "no-cache", header.Get("Pragma"))
			},
		},
		{
			debug: true,
			err:   ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().MaxTimes(2).Return(Arguments([]string{"token"}))
				req.EXPECT().GetRequestForm().Return(url.Values{})
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			checkHeader: func(t *testing.T, k int) {
				a, _ := url.Parse("https://foobar.com/?foo=bar#error=invalid_request&error_debug=with-debug&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed%0A%0AMake+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.%0A%0Awith-debug&error_hint=Make+sure+that+the+various+parameters+are+correct%2C+be+aware+of+case+sensitivity+and+trim+your+parameters.+Make+sure+that+the+client+you+are+using+has+exactly+whitelisted+the+redirect_uri+you+specified.&state=foostate")
				b, _ := url.Parse(header.Get("Location"))
				assert.Equal(t, a, b)
				assert.Equal(t, "no-store", header.Get("Cache-Control"))
				assert.Equal(t, "no-cache", header.Get("Pragma"))
			},
		},
		{
			debug: true,
			err:   ErrInvalidRequest.WithDebug("with-debug"),
			mock: func(rw *MockResponseWriter, req *MockAuthorizeRequester) {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(copyUrl(purls[1]))
				req.EXPECT().GetState().Return("foostate")
				req.EXPECT().GetResponseTypes().MaxTimes(2).Return(Arguments([]string{"token"}))
				req.EXPECT().GetRequestForm().Return(url.Values{"response_mode": {"form_post"}})
				rw.EXPECT().Header().Times(3).Return(header)
				rw.EXPECT().Write(gomock.Any()).AnyTimes()
			},
			checkHeader: func(t *testing.T, k int) {
				assert.Equal(t, "no-store", header.Get("Cache-Control"))
				assert.Equal(t, "no-cache", header.Get("Pragma"))
				assert.Equal(t, "text/html;charset=UTF-8", header.Get("Content-Type"))
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			oauth2 := &Fosite{
				SendDebugMessagesToClients: c.debug,
			}

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			rw := NewMockResponseWriter(ctrl)
			req := NewMockAuthorizeRequester(ctrl)

			c.mock(rw, req)
			oauth2.WriteAuthorizeError(rw, req, c.err)
			c.checkHeader(t, k)
			header = http.Header{}
		})
	}
}

func copyUrl(u *url.URL) *url.URL {
	u2, _ := url.Parse(u.String())
	return u2
}
