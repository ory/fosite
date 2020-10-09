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
	"html/template"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"
	goauth "golang.org/x/oauth2"

	"github.com/asaskevich/govalidator"
	"github.com/pkg/errors"
)

// MatchRedirectURIWithClientRedirectURIs if the given uri is a registered redirect uri. Does not perform
// uri validation.
//
// Considered specifications
// * https://tools.ietf.org/html/rfc6749#section-3.1.2.3
//   If multiple redirection URIs have been registered, if only part of
//   the redirection URI has been registered, or if no redirection URI has
//   been registered, the client MUST include a redirection URI with the
//   authorization request using the "redirect_uri" request parameter.
//
//   When a redirection URI is included in an authorization request, the
//   authorization server MUST compare and match the value received
//   against at least one of the registered redirection URIs (or URI
//   components) as defined in [RFC3986] Section 6, if any redirection
//   URIs were registered.  If the client registration included the full
//   redirection URI, the authorization server MUST compare the two URIs
//   using simple string comparison as defined in [RFC3986] Section 6.2.1.
//
// * https://tools.ietf.org/html/rfc6819#section-4.4.1.7
//   * The authorization server may also enforce the usage and validation
//     of pre-registered redirect URIs (see Section 5.2.3.5).  This will
//     allow for early recognition of authorization "code" disclosure to
//     counterfeit clients.
//   * The attacker will need to use another redirect URI for its
//     authorization process rather than the target web site because it
//     needs to intercept the flow.  So, if the authorization server
//     associates the authorization "code" with the redirect URI of a
//     particular end-user authorization and validates this redirect URI
//     with the redirect URI passed to the token's endpoint, such an
//     attack is detected (see Section 5.2.4.5).
func MatchRedirectURIWithClientRedirectURIs(rawurl string, client Client) (*url.URL, error) {
	if rawurl == "" && len(client.GetRedirectURIs()) == 1 {
		if redirectURIFromClient, err := url.Parse(client.GetRedirectURIs()[0]); err == nil && IsValidRedirectURI(redirectURIFromClient) {
			// If no redirect_uri was given and the client has exactly one valid redirect_uri registered, use that instead
			return redirectURIFromClient, nil
		}
	} else if redirectTo, ok := isMatchingRedirectURI(rawurl, client.GetRedirectURIs()); rawurl != "" && ok {
		// If a redirect_uri was given and the clients knows it (simple string comparison!)
		// return it.
		if parsed, err := url.Parse(redirectTo); err == nil && IsValidRedirectURI(parsed) {
			// If no redirect_uri was given and the client has exactly one valid redirect_uri registered, use that instead
			return parsed, nil
		}
	}

	return nil, errors.WithStack(ErrInvalidRequest.WithHint(`The "redirect_uri" parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls.`))
}

// Match a requested  redirect URI against a pool of registered client URIs
//
// Test a given redirect URI against a pool of URIs provided by a registered client.
// If the OAuth 2.0 Client has loopback URIs registered either an IPv4 URI http://127.0.0.1 or
// an IPv6 URI http://[::1] a client is allowed to request a dynamic port and the server MUST accept
// it as a valid redirection uri.
//
// https://tools.ietf.org/html/rfc8252#section-7.3
// Native apps that are able to open a port on the loopback network
// interface without needing special permissions (typically, those on
// desktop operating systems) can use the loopback interface to receive
// the OAuth redirect.
//
// Loopback redirect URIs use the "http" scheme and are constructed with
// the loopback IP literal and whatever port the client is listening on.
func isMatchingRedirectURI(uri string, haystack []string) (string, bool) {
	requested, err := url.Parse(uri)
	if err != nil {
		return "", false
	}

	for _, b := range haystack {
		if b == uri {
			return b, true
		} else if isMatchingAsLoopback(requested, b) {
			// We have to return the requested URL here because otherwise the port might get lost (see isMatchingAsLoopback)
			// description.
			return uri, true
		}
	}
	return "", false
}

func isMatchingAsLoopback(requested *url.URL, registeredURI string) bool {
	registered, err := url.Parse(registeredURI)
	if err != nil {
		return false
	}

	// Native apps that are able to open a port on the loopback network
	// interface without needing special permissions (typically, those on
	// desktop operating systems) can use the loopback interface to receive
	// the OAuth redirect.
	//
	// Loopback redirect URIs use the "http" scheme and are constructed with
	// the loopback IP literal and whatever port the client is listening on.
	//
	// Source: https://tools.ietf.org/html/rfc8252#section-7.3
	if requested.Scheme == "http" &&
		isLoopbackAddress(requested.Host) &&
		registered.Hostname() == requested.Hostname() &&
		// The port is skipped here - see codedoc above!
		registered.Path == requested.Path &&
		registered.RawQuery == requested.RawQuery {
		return true
	}

	return false
}

// Check if address is either an IPv4 loopback or an IPv6 loopback-
// An optional port is ignored
func isLoopbackAddress(address string) bool {
	match, _ := regexp.MatchString("^(127.0.0.1|\\[::1\\])(:?)(\\d*)$", address)
	return match
}

// IsValidRedirectURI validates a redirect_uri as specified in:
//
// * https://tools.ietf.org/html/rfc6749#section-3.1.2
//   * The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3.
//   * The endpoint URI MUST NOT include a fragment component.
// * https://tools.ietf.org/html/rfc3986#section-4.3
//   absolute-URI  = scheme ":" hier-part [ "?" query ]
// * https://tools.ietf.org/html/rfc6819#section-5.1.1
func IsValidRedirectURI(redirectURI *url.URL) bool {
	// We need to explicitly check for a scheme
	if !govalidator.IsRequestURL(redirectURI.String()) {
		return false
	}

	if redirectURI.Fragment != "" {
		// "The endpoint URI MUST NOT include a fragment component."
		return false
	}

	return true
}

func IsRedirectURISecure(redirectURI *url.URL) bool {
	return !(redirectURI.Scheme == "http" && !IsLocalhost(redirectURI))
}

func IsLocalhost(redirectURI *url.URL) bool {
	hn := redirectURI.Hostname()
	return strings.HasSuffix(hn, ".localhost") || hn == "127.0.0.1" || hn == "localhost"
}

func WriteAuthorizeFormPostResponse(redirectURL string, parameters url.Values, rw io.Writer) {
	t := template.Must(template.New("form_post").Parse(`<html>
   <head>
      <title>Submit This Form</title>
   </head>
   <body onload="javascript:document.forms[0].submit()">
      <form method="post" action="{{ .RedirURL }}">
         {{ range $key,$value := .Parameters }}
		<input type="hidden" name="{{$key}}" value="{{index $value 0}}"/>
         {{ end }}
      </form>
   </body>
</html>`))

	t.Execute(rw, struct {
		RedirURL   string
		Parameters url.Values
	}{
		RedirURL:   redirectURL,
		Parameters: parameters,
	})
}
func ParseFormPostResponse(redirectURL string, resp io.ReadCloser) (authorizationCode, stateFromServer, iDToken string, token goauth.Token, rFC6749Error RFC6749Error, err error) {

	token = goauth.Token{}
	rFC6749Error = RFC6749Error{}

	doc, err := html.Parse(resp)
	if err != nil {
		return "", "", "", token, rFC6749Error, err
	}
	//doc>html>body
	body := findBody(doc.FirstChild.FirstChild)
	if body.Data != "body" {
		return "", "", "", token, rFC6749Error, errors.New("Malformed html")
	}
	htmlEvent := body.Attr[0].Key
	if htmlEvent != "onload" {
		return "", "", "", token, rFC6749Error, errors.New("onload event is missing")
	}
	onLoadFunc := body.Attr[0].Val
	if onLoadFunc != "javascript:document.forms[0].submit()" {
		return "", "", "", token, rFC6749Error, errors.New("onload function is missing")
	}
	form := getNextNoneTextNode(body.FirstChild)
	if form.Data != "form" {
		return "", "", "", token, rFC6749Error, errors.New("html form is missing")
	}
	for _, attr := range form.Attr {
		if attr.Key == "method" {
			if attr.Val != "post" {
				return "", "", "", token, rFC6749Error, errors.New("html form post method is missing")
			}
		} else {
			if attr.Val != redirectURL {
				return "", "", "", token, rFC6749Error, errors.New("html form post url is wrong")
			}
		}
	}

	for node := getNextNoneTextNode(form.FirstChild); node != nil; node = getNextNoneTextNode(node.NextSibling) {
		var k, v string
		for _, attr := range node.Attr {
			if attr.Key == "name" {
				k = attr.Val
			} else if attr.Key == "value" {
				v = attr.Val
			}

		}
		switch k {
		case "state":
			stateFromServer = v
		case "code":
			authorizationCode = v
		case "expires_in":
			expires, err := strconv.Atoi(v)
			if err != nil {
				return "", "", "", token, rFC6749Error, err
			}
			token.Expiry = time.Now().UTC().Add(time.Duration(expires) * time.Second)
		case "access_token":
			token.AccessToken = v
		case "token_type":
			token.TokenType = v
		case "refresh_token":
			token.RefreshToken = v
		case "error":
			rFC6749Error.Name = v
		case "error_description":
			rFC6749Error.Description = v
		case "id_token":
			iDToken = v
		}
	}
	return
}

func getNextNoneTextNode(node *html.Node) *html.Node {
	nextNode := node.NextSibling
	if nextNode != nil && nextNode.Type == html.TextNode {
		nextNode = getNextNoneTextNode(node.NextSibling)
	}
	return nextNode
}
func findBody(node *html.Node) *html.Node {
	if node != nil {
		if node.Data == "body" {
			return node
		}
		return findBody(node.NextSibling)
	}
	return nil
}
