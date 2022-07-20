/*
 * Copyright © 2015-2020 Aeneas Rekkas <aeneas+oss@aeneas.io>
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
 * @copyright 	2015-2020 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"io"
	"strconv"
	"time"

	cristaljwt "github.com/cristalhq/jwt/v4"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
	goauth "golang.org/x/oauth2"

	fosite "github.com/ory/fosite"
)

func ptr(d time.Duration) *time.Duration {
	return &d
}

var TestLifespans fosite.ClientLifespanConfig = fosite.ClientLifespanConfig{
	AuthorizationCodeGrantAccessTokenLifespan:  ptr(31 * time.Hour),
	AuthorizationCodeGrantIDTokenLifespan:      ptr(32 * time.Hour),
	AuthorizationCodeGrantRefreshTokenLifespan: ptr(33 * time.Hour),
	ClientCredentialsGrantAccessTokenLifespan:  ptr(34 * time.Hour),
	ImplicitGrantAccessTokenLifespan:           ptr(35 * time.Hour),
	ImplicitGrantIDTokenLifespan:               ptr(36 * time.Hour),
	JwtBearerGrantAccessTokenLifespan:          ptr(37 * time.Hour),
	PasswordGrantAccessTokenLifespan:           ptr(38 * time.Hour),
	PasswordGrantRefreshTokenLifespan:          ptr(39 * time.Hour),
	RefreshTokenGrantIDTokenLifespan:           ptr(40 * time.Hour),
	RefreshTokenGrantAccessTokenLifespan:       ptr(41 * time.Hour),
	RefreshTokenGrantRefreshTokenLifespan:      ptr(42 * time.Hour),
}

func RequireEqualDuration(t *testing.T, expected time.Duration, actual time.Duration, precision time.Duration) {
	delta := expected - actual
	if delta < 0 {
		delta = -delta
	}
	require.Less(t, delta, precision, fmt.Sprintf("expected %s; got %s", expected, actual))
}

func RequireEqualTime(t *testing.T, expected time.Time, actual time.Time, precision time.Duration) {
	delta := expected.Sub(actual)
	if delta < 0 {
		delta = -delta
	}
	require.Less(t, delta, precision, fmt.Sprintf(
		"expected %s; got %s",
		expected.Format(time.RFC3339Nano),
		actual.Format(time.RFC3339Nano),
	))
}

func ExtractJwtExpClaim(t *testing.T, token string) *time.Time {
	jwt, err := cristaljwt.ParseNoVerify([]byte(token))
	require.NoError(t, err)
	claims := &cristaljwt.RegisteredClaims{}
	require.NoError(t, json.Unmarshal(jwt.Claims(), claims))
	if claims.ExpiresAt == nil {
		return nil
	}
	return &claims.ExpiresAt.Time
}

func ParseFormPostResponse(redirectURL string, resp io.ReadCloser) (authorizationCode, stateFromServer, iDToken string, token goauth.Token, customParameters url.Values, rFC6749Error map[string]string, err error) {
	token = goauth.Token{}
	rFC6749Error = map[string]string{}
	customParameters = url.Values{}

	doc, err := html.Parse(resp)
	if err != nil {
		return "", "", "", token, customParameters, rFC6749Error, err
	}

	//doc>html>body
	body := findBody(doc.FirstChild.FirstChild)
	if body.Data != "body" {
		return "", "", "", token, customParameters, rFC6749Error, errors.New("Malformed html")
	}

	htmlEvent := body.Attr[0].Key
	if htmlEvent != "onload" {
		return "", "", "", token, customParameters, rFC6749Error, errors.New("onload event is missing")
	}

	onLoadFunc := body.Attr[0].Val
	if onLoadFunc != "javascript:document.forms[0].submit()" {
		return "", "", "", token, customParameters, rFC6749Error, errors.New("onload function is missing")
	}

	form := getNextNoneTextNode(body.FirstChild)
	if form.Data != "form" {
		return "", "", "", token, customParameters, rFC6749Error, errors.New("html form is missing")
	}

	for _, attr := range form.Attr {
		if attr.Key == "method" {
			if attr.Val != "post" {
				return "", "", "", token, customParameters, rFC6749Error, errors.New("html form post method is missing")
			}
		} else {
			if attr.Val != redirectURL {
				return "", "", "", token, customParameters, rFC6749Error, errors.New("html form post url is wrong")
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
				return "", "", "", token, customParameters, rFC6749Error, err
			}
			token.Expiry = time.Now().UTC().Add(time.Duration(expires) * time.Second)
		case "access_token":
			token.AccessToken = v
		case "token_type":
			token.TokenType = v
		case "refresh_token":
			token.RefreshToken = v
		case "error":
			rFC6749Error["ErrorField"] = v
		case "error_hint":
			rFC6749Error["HintField"] = v
		case "error_description":
			rFC6749Error["DescriptionField"] = v
		case "id_token":
			iDToken = v
		default:
			customParameters.Add(k, v)
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
