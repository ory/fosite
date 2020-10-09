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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthorizeResponse(t *testing.T) {
	ar := NewAuthorizeResponse()
	ar.AddFragment("foo", "bar")
	ar.AddQuery("foo", "baz")
	ar.AddHeader("foo", "foo")
	ar.AddForm("bar", "bar")

	ar.AddFragment("code", "bar")
	assert.Equal(t, "bar", ar.GetCode())
	ar.AddQuery("code", "baz")
	assert.Equal(t, "baz", ar.GetCode())
	ar.AddForm("code", "baz")
	assert.Equal(t, "baz", ar.GetCode())

	assert.Equal(t, "bar", ar.GetFragment().Get("foo"))
	assert.Equal(t, "baz", ar.GetQuery().Get("foo"))
	assert.Equal(t, "foo", ar.GetHeader().Get("foo"))
	assert.Equal(t, "bar", ar.GetForm().Get("bar"))
}
