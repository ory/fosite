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
	"strings"

	"context"

	"fmt"

	"github.com/pkg/errors"
)

func (c *Fosite) NewAuthorizeRequest(ctx context.Context, r *http.Request) (AuthorizeRequester, error) {
	request := &AuthorizeRequest{
		ResponseTypes:        Arguments{},
		HandledResponseTypes: Arguments{},
		Request:              *NewRequest(),
	}

	if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return request, errors.WithStack(ErrInvalidRequest.WithDebug(err.Error()))
	}

	request.Form = r.Form
	client, err := c.Store.GetClient(ctx, request.GetRequestForm().Get("client_id"))
	if err != nil {
		return request, errors.WithStack(ErrInvalidClient)
	}
	request.Client = client

	scope := removeEmpty(strings.Split(r.Form.Get("scope"), " "))
	for _, permission := range scope {
		if !c.ScopeStrategy(client.GetScopes(), permission) {
			return request, errors.WithStack(ErrInvalidScope.WithDebug(fmt.Sprintf("The client is not allowed to request scope %s", permission)))
		}
	}

	// Fetch redirect URI from request
	rawRedirURI, err := GetRedirectURIFromRequestValues(r.Form)
	if err != nil {
		return request, errors.WithStack(ErrInvalidRequest.WithDebug(err.Error()))
	}

	// Validate redirect uri
	redirectURI, err := MatchRedirectURIWithClientRedirectURIs(rawRedirURI, client)
	if err != nil {
		return request, errors.WithStack(ErrInvalidRequest.WithDebug(err.Error()))
	} else if !IsValidRedirectURI(redirectURI) {
		return request, errors.WithStack(ErrInvalidRequest.WithDebug("not a valid redirect uri"))
	}
	request.RedirectURI = redirectURI

	// https://tools.ietf.org/html/rfc6749#section-3.1.1
	// Extension response types MAY contain a space-delimited (%x20) list of
	// values, where the order of values does not matter (e.g., response
	// type "a b" is the same as "b a").  The meaning of such composite
	// response types is defined by their respective specifications.
	request.ResponseTypes = removeEmpty(strings.Split(r.Form.Get("response_type"), " "))

	// rfc6819 4.4.1.8.  Threat: CSRF Attack against redirect-uri
	// The "state" parameter should be used to link the authorization
	// request with the redirect URI used to deliver the access token (Section 5.3.5).
	//
	// https://tools.ietf.org/html/rfc6819#section-4.4.1.8
	// The "state" parameter should not	be guessable
	state := r.Form.Get("state")
	if len(state) < MinParameterEntropy {
		// We're assuming that using less then 8 characters for the state can not be considered "unguessable"
		return request, errors.WithStack(ErrInvalidState.WithDebug(fmt.Sprintf("State length must at least be %d characters long", MinParameterEntropy)))
	}
	request.State = state

	if len(request.Form.Get("request")) > 0 {
		return request, errors.WithStack(ErrRequestNotSupported)
	}

	if len(request.Form.Get("request_uri")) > 0 {
		return request, errors.WithStack(ErrRequestURINotSupported)
	}

	if len(request.Form.Get("registration")) > 0 {
		return request, errors.WithStack(ErrRegistrationNotSupported)
	}

	// Remove empty items from arrays
	request.SetRequestedScopes(scope)
	return request, nil
}
