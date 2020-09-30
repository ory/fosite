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
	"fmt"
	"strings"
)

// StringInSlice returns true if needle exists in haystack
func StringInSlice(needle string, haystack []string) bool {
	for _, b := range haystack {
		if strings.ToLower(b) == strings.ToLower(needle) {
			return true
		}
	}
	return false
}

func RemoveEmpty(args []string) (ret []string) {
	for _, v := range args {
		v = strings.TrimSpace(v)
		if v != "" {
			ret = append(ret, v)
		}
	}
	return
}

// EscapeJSONString does a poor man's JSON encoding. Useful when we do not want to use full JSON encoding
// because we just had an error doing the JSON encoding. The characters that MUST be escaped: quotation mark,
// reverse solidus, and the control characters (U+0000 through U+001F).
// See: https://tools.ietf.org/html/std90#section-7
func EscapeJSONString(str string) string {
	// Escape reverse solidus.
	str = strings.ReplaceAll(str, `\`, `\\`)
	// Escape control characters.
	for r := rune(0); r < ' '; r++ {
		str = strings.ReplaceAll(str, string(r), fmt.Sprintf(`\u%04x`, r))
	}
	// Escape quotation mark.
	str = strings.ReplaceAll(str, `"`, `\"`)
	return str
}
