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

import "strings"

type Arguments []string

// Matches performs an case-insensitive, out-of-order check that the items
// provided exist and equal all of the args in arguments.
// Note:
//   - Providing a list that includes duplicate string-case items will return not
//     matched.
func (r Arguments) Matches(items ...string) bool {
	if len(r) != len(items) {
		return false
	}

	found := make(map[string]bool)
	for _, item := range items {
		if !StringInSlice(item, r) {
			return false
		}
		found[item] = true
	}

	return len(found) == len(r)
}

// Has checks, in a case-insensitive manner, that all of the items
// provided exists in arguments.
func (r Arguments) Has(items ...string) bool {
	for _, item := range items {
		if !StringInSlice(item, r) {
			return false
		}
	}

	return true
}

// HasOneOf checks, in a case-insensitive manner, that one of the items
// provided exists in arguments.
func (r Arguments) HasOneOf(items ...string) bool {
	for _, item := range items {
		if StringInSlice(item, r) {
			return true
		}
	}

	return false
}

// Deprecated: Use ExactOne, Matches or MatchesExact
func (r Arguments) Exact(name string) bool {
	return name == strings.Join(r, " ")
}

// ExactOne checks, by string case, that a single argument equals the provided
// string.
func (r Arguments) ExactOne(name string) bool {
	return len(r) == 1 && r[0] == name
}

// MatchesExact checks, by order and string case, that the items provided equal
// those in arguments.
func (r Arguments) MatchesExact(items ...string) bool {
	if len(r) != len(items) {
		return false
	}

	for i, item := range items {
		if item != r[i] {
			return false
		}
	}

	return true
}
