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
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateResponseTypes(t *testing.T) {
	f := &Fosite{Config: new(Config)}
	for k, tc := range []struct {
		rt        string
		art       []string
		expectErr bool
	}{
		{
			rt:        "code",
			art:       []string{"token"},
			expectErr: true,
		},
		{
			rt:  "token",
			art: []string{"token"},
		},
		{
			rt:        "",
			art:       []string{"token"},
			expectErr: true,
		},
		{
			rt:        "  ",
			art:       []string{"token"},
			expectErr: true,
		},
		{
			rt:        "disable",
			art:       []string{"token"},
			expectErr: true,
		},
		{
			rt:        "code token",
			art:       []string{"token", "code"},
			expectErr: true,
		},
		{
			rt:  "code token",
			art: []string{"token", "token code"},
		},
		{
			rt:  "code token",
			art: []string{"token", "code token"},
		},
		{
			rt:        "code token",
			art:       []string{"token", "code token id_token"},
			expectErr: true,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			r := &http.Request{Form: url.Values{"response_type": {tc.rt}}}
			if tc.rt == "disable" {
				r = &http.Request{Form: url.Values{}}
			}
			ar := NewAuthorizeRequest()
			ar.Request.Client = &DefaultClient{ResponseTypes: tc.art}

			err := f.validateResponseTypes(r, ar)
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.EqualValues(t, RemoveEmpty(strings.Split(tc.rt, " ")), ar.GetResponseTypes())
			}
		})
	}
}
