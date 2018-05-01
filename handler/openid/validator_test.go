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

package openid

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
)

func TestValidatePrompt(t *testing.T) {
	v := NewOpenIDConnectRequestValidator(nil)

	for k, tc := range []struct {
		prompt    string
		isPublic  bool
		expectErr bool
	}{
		{
			prompt:    "none",
			isPublic:  true,
			expectErr: true,
		},
		{
			prompt:    "none",
			isPublic:  false,
			expectErr: false,
		},
		{
			prompt:    "none login",
			isPublic:  false,
			expectErr: true,
		},
		{
			prompt:    "foo",
			isPublic:  false,
			expectErr: true,
		},
		{
			prompt:    "login consent",
			isPublic:  true,
			expectErr: false,
		},
		{
			prompt:    "login consent",
			isPublic:  false,
			expectErr: false,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			err := v.ValidatePrompt(&fosite.AuthorizeRequest{
				Request: fosite.Request{
					Form:   url.Values{"prompt": {tc.prompt}},
					Client: &fosite.DefaultClient{Public: tc.isPublic},
				},
			})
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
