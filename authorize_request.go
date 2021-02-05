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
	"net/url"
)

type ResponseModeType string

const (
	ResponseModeDefault  = ResponseModeType("")
	ResponseModeFormPost = ResponseModeType("form_post")
	ResponseModeQuery    = ResponseModeType("query")
	ResponseModeFragment = ResponseModeType("fragment")
)

// AuthorizeRequest is an implementation of AuthorizeRequester
type AuthorizeRequest struct {
	ResponseTypes        Arguments        `json:"responseTypes" gorethink:"responseTypes"`
	RedirectURI          *url.URL         `json:"redirectUri" gorethink:"redirectUri"`
	State                string           `json:"state" gorethink:"state"`
	HandledResponseTypes Arguments        `json:"handledResponseTypes" gorethink:"handledResponseTypes"`
	ResponseMode         ResponseModeType `json:"ResponseModes" gorethink:"ResponseModes"`
	DefaultResponseMode  ResponseModeType `json:"DefaultResponseMode" gorethink:"DefaultResponseMode"`

	Request
}

func NewAuthorizeRequest() *AuthorizeRequest {
	return &AuthorizeRequest{
		ResponseTypes:        Arguments{},
		HandledResponseTypes: Arguments{},
		Request:              *NewRequest(),
		ResponseMode:         ResponseModeDefault,
		// The redirect URL must be unset / nil for redirect detection to work properly:
		// RedirectURI:          &url.URL{},
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

func (d *AuthorizeRequest) GetResponseMode() ResponseModeType {
	return d.ResponseMode
}

func (d *AuthorizeRequest) SetDefaultResponseMode(defaultResponseMode ResponseModeType) {
	if d.ResponseMode == ResponseModeDefault {
		d.ResponseMode = defaultResponseMode
	}
	d.DefaultResponseMode = defaultResponseMode
}

func (d *AuthorizeRequest) GetDefaultResponseMode() ResponseModeType {
	return d.DefaultResponseMode
}
