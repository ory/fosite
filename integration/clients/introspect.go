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

package clients

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type IntrospectForm struct {
	Token  string
	Scopes []string
}

type IntrospectResponse struct {
	Active    bool     `json:"active"`
	ClientID  string   `json:"client_id,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Username  string   `json:"username,omitempty"`
}

type Introspect struct {
	url    string
	client *http.Client
}

func (c *Introspect) IntrospectToken(
	ctx context.Context,
	form IntrospectForm,
	header map[string]string,
) (*IntrospectResponse, error) {
	data := url.Values{}
	data.Set("token", form.Token)
	data.Set("scope", strings.Join(form.Scopes, " "))

	request, err := c.getRequest(ctx, data, header)
	if err != nil {
		return nil, err
	}

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if c := response.StatusCode; c < 200 || c > 299 {
		return nil, &RequestError{
			Response: response,
			Body:     body,
		}
	}

	result := &IntrospectResponse{}

	if err := json.Unmarshal(body, result); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Introspect) getRequest(
	ctx context.Context,
	data url.Values,
	header map[string]string,
) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, "POST", c.url, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	for header, value := range header {
		request.Header.Set(header, value)
	}

	return request, nil
}

func NewIntrospectClient(url string) *Introspect {
	return &Introspect{
		url:    url,
		client: &http.Client{},
	}
}
