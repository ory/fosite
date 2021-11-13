/*
 * Copyright © 2017-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
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
 * @Copyright 	2017-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package openid

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
	"github.com/ory/go-convenience/stringslice"
)

type OpenIDConnectRequestValidator struct {
	AllowedPrompt       []string
	Strategy            jwt.JWTStrategy
	IsRedirectURISecure func(*url.URL) bool
}

func NewOpenIDConnectRequestValidator(prompt []string, strategy jwt.JWTStrategy) *OpenIDConnectRequestValidator {
	if len(prompt) == 0 {
		prompt = []string{"login", "none", "consent", "select_account"}
	}

	return &OpenIDConnectRequestValidator{
		AllowedPrompt: prompt,
		Strategy:      strategy,
	}
}

func (v *OpenIDConnectRequestValidator) WithRedirectSecureChecker(checker func(*url.URL) bool) *OpenIDConnectRequestValidator {
	v.IsRedirectURISecure = checker
	return v
}

func (v *OpenIDConnectRequestValidator) secureChecker() func(*url.URL) bool {
	if v.IsRedirectURISecure == nil {
		v.IsRedirectURISecure = fosite.IsRedirectURISecure
	}
	return v.IsRedirectURISecure
}

func (v *OpenIDConnectRequestValidator) ValidatePrompt(ctx context.Context, req fosite.AuthorizeRequester) error {
	// prompt is case sensitive!
	prompt := fosite.RemoveEmpty(strings.Split(req.GetRequestForm().Get("prompt"), " "))

	if req.GetClient().IsPublic() {
		// Threat: Malicious Client Obtains Existing Authorization by Fraud
		// https://tools.ietf.org/html/rfc6819#section-4.2.3
		//
		//  Authorization servers should not automatically process repeat
		//  authorizations to public clients unless the client is validated
		//  using a pre-registered redirect URI

		// Client Impersonation
		// https://tools.ietf.org/html/rfc8252#section-8.6#
		//
		//  As stated in Section 10.2 of OAuth 2.0 [RFC6749], the authorization
		//  server SHOULD NOT process authorization requests automatically
		//  without user consent or interaction, except when the identity of the
		//  client can be assured.  This includes the case where the user has
		//  previously approved an authorization request for a given client id --
		//  unless the identity of the client can be proven, the request SHOULD
		//  be processed as if no previous request had been approved.

		if stringslice.Has(prompt, "none") {
			if !v.secureChecker()(req.GetRedirectURI()) {
				return errorsx.WithStack(fosite.ErrConsentRequired.WithHint("OAuth 2.0 Client is marked public and redirect uri is not considered secure (https missing), but \"prompt=none\" was requested."))
			}
		}
	}

	if !isWhitelisted(prompt, v.AllowedPrompt) {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("Used unknown value '%s' for prompt parameter", prompt))
	}

	if stringslice.Has(prompt, "none") && len(prompt) > 1 {
		// If this parameter contains none with any other value, an error is returned.
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Parameter 'prompt' was set to 'none', but contains other values as well which is not allowed."))
	}

	maxAge, err := strconv.ParseInt(req.GetRequestForm().Get("max_age"), 10, 64)
	if err != nil {
		maxAge = 0
	}

	session, ok := req.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to validate OpenID Connect request because session is not of type fosite/handler/openid.Session."))
	}

	claims := session.IDTokenClaims()
	if claims.Subject == "" {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to validate OpenID Connect request because session subject is empty."))
	}

	// Adds a bit of wiggle room for timing issues
	if claims.AuthTime.After(time.Now().UTC().Add(time.Second * 5)) {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to validate OpenID Connect request because authentication time is in the future."))
	}

	if maxAge > 0 {
		if claims.AuthTime.IsZero() {
			return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to validate OpenID Connect request because authentication time claim is required when max_age is set."))
		} else if claims.RequestedAt.IsZero() {
			return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to validate OpenID Connect request because requested at claim is required when max_age is set."))
		} else if claims.AuthTime.Add(time.Second * time.Duration(maxAge)).Before(claims.RequestedAt) {
			return errorsx.WithStack(fosite.ErrLoginRequired.WithDebug("Failed to validate OpenID Connect request because authentication time does not satisfy max_age time."))
		}
	}

	if stringslice.Has(prompt, "none") {
		if claims.AuthTime.IsZero() {
			return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to validate OpenID Connect request because because auth_time is missing from session."))
		}
		if !claims.AuthTime.Equal(claims.RequestedAt) && claims.AuthTime.After(claims.RequestedAt) {
			// !claims.AuthTime.Truncate(time.Second).Equal(claims.RequestedAt) && claims.AuthTime.Truncate(time.Second).Before(claims.RequestedAt) {
			return errorsx.WithStack(fosite.ErrLoginRequired.WithHintf("Failed to validate OpenID Connect request because prompt was set to 'none' but auth_time ('%s') happened after the authorization request ('%s') was registered, indicating that the user was logged in during this request which is not allowed.", claims.AuthTime, claims.RequestedAt))
		}
	}

	if stringslice.Has(prompt, "login") {
		if claims.AuthTime.Before(claims.RequestedAt) {
			return errorsx.WithStack(fosite.ErrLoginRequired.WithHintf("Failed to validate OpenID Connect request because prompt was set to 'login' but auth_time ('%s') happened before the authorization request ('%s') was registered, indicating that the user was not re-authenticated which is forbidden.", claims.AuthTime, claims.RequestedAt))
		}
	}

	idTokenHint := req.GetRequestForm().Get("id_token_hint")
	if idTokenHint == "" {
		return nil
	}

	tokenHint, err := v.Strategy.Decode(ctx, idTokenHint)
	var ve *jwt.ValidationError
	if errors.As(err, &ve) && ve.Has(jwt.ValidationErrorExpired) {
		// Expired tokens are ok
	} else if err != nil {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Failed to validate OpenID Connect request as decoding id token from id_token_hint parameter failed.").WithWrap(err).WithDebug(err.Error()))
	}

	if hintSub, _ := tokenHint.Claims["sub"].(string); hintSub == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Failed to validate OpenID Connect request because provided id token from id_token_hint does not have a subject."))
	} else if hintSub != claims.Subject {
		return errorsx.WithStack(fosite.ErrLoginRequired.WithHint("Failed to validate OpenID Connect request because the subject from provided id token from id_token_hint does not match the current session's subject."))
	}

	return nil
}

func isWhitelisted(items []string, whiteList []string) bool {
	for _, item := range items {
		if !stringslice.Has(whiteList, item) {
			return false
		}
	}
	return true
}
