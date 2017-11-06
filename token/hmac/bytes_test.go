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

package hmac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandomBytes(t *testing.T) {
	bytes, err := RandomBytes(128)
	assert.NoError(t, err)
	assert.Len(t, bytes, 128)
}

func TestPseudoRandomness(t *testing.T) {
	runs := 65536
	results := map[string]bool{}
	for i := 0; i < runs; i++ {
		bytes, err := RandomBytes(128)
		assert.NoError(t, err)

		_, ok := results[string(bytes)]
		assert.False(t, ok)
		results[string(bytes)] = true
	}
}
