// Copyright © 2017 Aeneas Rekkas <aeneas+oss@aeneas.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fosite

import (
	"net/url"
)

// AuthorizeRequest is an implementation of AuthorizeRequester
type AuthorizeRequest struct {
	ResponseTypes        Arguments `json:"responseTypes" gorethink:"responseTypes"`
	RedirectURI          *url.URL  `json:"redirectUri" gorethink:"redirectUri"`
	State                string    `json:"state" gorethink:"state"`
	HandledResponseTypes Arguments `json:"handledResponseTypes" gorethink:"handledResponseTypes"`

	// Optional code_challenge as described in rfc7636
	CodeChallenge string `json:"code_challenge" gorethink:"code_challenge"`
	// Optional code_challenge_method as described in rfc7636
	CodeChallengeMethod string `json:"code_challenge_method" gorethink:"code_challenge_method"`

	Request
}

func NewAuthorizeRequest() *AuthorizeRequest {
	return &AuthorizeRequest{
		ResponseTypes:        Arguments{},
		RedirectURI:          &url.URL{},
		HandledResponseTypes: Arguments{},
		Request:              *NewRequest(),
	}
}

func (d *AuthorizeRequest) IsRedirectURIValid() bool {
	if d.GetRedirectURI() == nil {
		return false
	}

	raw := d.GetRedirectURI().String()
	if d.GetClient() == nil {
		return false
	}

	redirectURI, err := MatchRedirectURIWithClientRedirectURIs(raw, d.GetClient())
	if err != nil {
		return false
	}
	return IsValidRedirectURI(redirectURI)
}

func (d *AuthorizeRequest) GetResponseTypes() Arguments {
	return d.ResponseTypes
}

func (d *AuthorizeRequest) GetState() string {
	return d.State
}

func (d *AuthorizeRequest) GetCodeChallenge() string {
	return d.CodeChallenge
}

func (d *AuthorizeRequest) GetCodeChallengeMethod() string {
	return d.CodeChallengeMethod
}

func (d *AuthorizeRequest) GetRedirectURI() *url.URL {
	return d.RedirectURI
}

func (d *AuthorizeRequest) SetResponseTypeHandled(name string) {
	d.HandledResponseTypes = append(d.HandledResponseTypes, name)
}

func (d *AuthorizeRequest) DidHandleAllResponseTypes() bool {
	for _, rt := range d.ResponseTypes {
		if !d.HandledResponseTypes.Has(rt) {
			return false
		}
	}

	return len(d.ResponseTypes) > 0
}
