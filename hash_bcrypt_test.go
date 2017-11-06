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

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
)

func TestHash(t *testing.T) {
	h := &BCrypt{
		WorkFactor: 10,
	}
	password := []byte("foo")
	hash, err := h.Hash(password)
	assert.NoError(t, err)
	assert.NotNil(t, hash)
	assert.NotEqual(t, hash, password)
}

func TestCompareEquals(t *testing.T) {
	h := &BCrypt{
		WorkFactor: 10,
	}
	password := []byte("foo")
	hash, err := h.Hash(password)
	assert.NoError(t, err)
	assert.NotNil(t, hash)
	err = h.Compare(hash, password)
	assert.NoError(t, err)
}

func TestCompareDifferent(t *testing.T) {
	h := &BCrypt{
		WorkFactor: 10,
	}
	password := []byte("foo")
	hash, err := h.Hash(password)
	assert.NoError(t, err)
	assert.NotNil(t, hash)
	err = h.Compare(hash, []byte(uuid.NewRandom()))
	assert.Error(t, err)
}
