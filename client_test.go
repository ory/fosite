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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultClient(t *testing.T) {
	sc := &DefaultClient{
		ID:            "1",
		Secret:        []byte("foobar-"),
		RedirectURIs:  []string{"foo", "bar"},
		ResponseTypes: []string{"foo", "bar"},
		GrantTypes:    []string{"foo", "bar"},
		Scopes:        []string{"fooscope"},
	}

	assert.Equal(t, sc.ID, sc.GetID())
	assert.Equal(t, sc.RedirectURIs, sc.GetRedirectURIs())
	assert.Equal(t, sc.Secret, sc.GetHashedSecret())
	assert.EqualValues(t, sc.ResponseTypes, sc.GetResponseTypes())
	assert.EqualValues(t, sc.GrantTypes, sc.GetGrantTypes())
	assert.EqualValues(t, sc.Scopes, sc.GetScopes())

	sc.GrantTypes = []string{}
	sc.ResponseTypes = []string{}
	assert.Equal(t, "code", sc.GetResponseTypes()[0])
	assert.Equal(t, "authorization_code", sc.GetGrantTypes()[0])
}
