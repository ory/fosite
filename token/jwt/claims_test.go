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

package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestToString(t *testing.T) {
	assert.Equal(t, "foo", ToString("foo"))
	assert.Equal(t, "foo", ToString([]string{"foo"}))
	assert.Empty(t, ToString(1234))
	assert.Empty(t, ToString(nil))
}

func TestToTime(t *testing.T) {
	assert.Equal(t, time.Time{}, ToTime(nil))
	assert.Equal(t, time.Time{}, ToTime("1234"))

	now := time.Now().UTC().Round(time.Second)
	assert.Equal(t, now, ToTime(now))
	assert.Equal(t, now, ToTime(now.Unix()))
	assert.Equal(t, now, ToTime(float64(now.Unix())))
}
