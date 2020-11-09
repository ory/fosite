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

package fosite

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/ory/x/errorsx"

	jose "gopkg.in/square/go-jose.v2"
)

// JWKSFetcherStrategy is a strategy which pulls (optionally caches) JSON Web Key Sets from a location,
// typically a client's jwks_uri.
type JWKSFetcherStrategy interface {
	// Resolve returns the JSON Web Key Set, or an error if something went wrong. The forceRefresh, if true, forces
	// the strategy to fetch the keys from the remote. If forceRefresh is false, the strategy may use a caching strategy
	// to fetch the key.
	Resolve(location string, forceRefresh bool) (*jose.JSONWebKeySet, error)
}

type DefaultJWKSFetcherStrategy struct {
	client *http.Client
	keys   map[string]jose.JSONWebKeySet
	sync.Mutex
}

func NewDefaultJWKSFetcherStrategy() JWKSFetcherStrategy {
	return &DefaultJWKSFetcherStrategy{
		keys:   make(map[string]jose.JSONWebKeySet),
		client: http.DefaultClient,
	}
}

func (s *DefaultJWKSFetcherStrategy) Resolve(location string, forceRefresh bool) (*jose.JSONWebKeySet, error) {
	s.Lock()
	defer s.Unlock()

	keys, ok := s.keys[location]
	if !ok || forceRefresh {
		response, err := s.client.Get(location)
		if err != nil {
			return nil, errorsx.WithStack(ErrServerError.WithHintf("Unable to fetch JSON Web Keys from location '%s'. Check for typos or other network issues.", location).WithWrap(err).WithDebug(err.Error()))
		}
		defer response.Body.Close()

		if response.StatusCode < 200 || response.StatusCode >= 400 {
			return nil, errorsx.WithStack(ErrServerError.WithHintf("Expected successful status code in range of 200 - 399 from location '%s' but received code %d.", location, response.StatusCode))
		}

		var set jose.JSONWebKeySet
		if err := json.NewDecoder(response.Body).Decode(&set); err != nil {
			return nil, errorsx.WithStack(ErrServerError.WithHintf("Unable to decode JSON Web Keys from location '%s'. Please check for typos and if the URL returns valid JSON.", location).WithWrap(err).WithDebug(err.Error()))
		}

		s.keys[location] = set
		return &set, nil
	}

	return &keys, nil
}
