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

package fosite_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	jose "gopkg.in/square/go-jose.v2"

	. "github.com/ory/fosite"
	"github.com/ory/fosite/internal"
)

func TestDefaultJWKSFetcherStrategy(t *testing.T) {
	var h http.HandlerFunc

	s := NewDefaultJWKSFetcherStrategy()
	t.Run("case=fetching", func(t *testing.T) {
		var set *jose.JSONWebKeySet
		h = func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, json.NewEncoder(w).Encode(set))
		}
		ts := httptest.NewServer(h)
		defer ts.Close()

		set = &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					KeyID: "foo",
					Use:   "sig",
					Key:   &internal.MustRSAKey().PublicKey,
				},
			},
		}

		keys, err := s.Resolve(ts.URL, false)
		require.NoError(t, err)
		assert.True(t, len(keys.Key("foo")) == 1)

		set = &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					KeyID: "bar",
					Use:   "sig",
					Key:   &internal.MustRSAKey().PublicKey,
				},
			},
		}

		keys, err = s.Resolve(ts.URL, false)
		require.NoError(t, err)
		assert.True(t, len(keys.Key("foo")) == 1)
		assert.True(t, len(keys.Key("bar")) == 0)

		keys, err = s.Resolve(ts.URL, true)
		require.NoError(t, err)
		assert.True(t, len(keys.Key("foo")) == 0)
		assert.True(t, len(keys.Key("bar")) == 1)
	})

	t.Run("case=error_network", func(t *testing.T) {
		h = func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
		}
		ts := httptest.NewServer(h)
		defer ts.Close()

		_, err := s.Resolve(ts.URL, true)
		require.Error(t, err)

		_, err = s.Resolve("$%/19", true)
		require.Error(t, err)
	})

	t.Run("case=error_encoding", func(t *testing.T) {
		h = func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("[]"))
		}
		ts := httptest.NewServer(h)
		defer ts.Close()

		_, err := s.Resolve(ts.URL, true)
		require.Error(t, err)
	})
}
