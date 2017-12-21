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

func TestArgumentsExact(t *testing.T) {
	for k, c := range []struct {
		args   Arguments
		exact  string
		expect bool
	}{
		{
			args:   Arguments{"foo"},
			exact:  "foo",
			expect: true,
		},
		{
			args:   Arguments{"foo", "bar"},
			exact:  "foo",
			expect: false,
		},
		{
			args:   Arguments{"foo", "bar"},
			exact:  "bar",
			expect: false,
		},
		{
			args:   Arguments{"foo", "bar"},
			exact:  "baz",
			expect: false,
		},
		{
			args:   Arguments{},
			exact:  "baz",
			expect: false,
		},
	} {
		assert.Equal(t, c.expect, c.args.Exact(c.exact), "%d", k)
		t.Logf("Passed test case %d", k)
	}
}

func TestArgumentsHas(t *testing.T) {
	for k, c := range []struct {
		args   Arguments
		has    []string
		expect bool
	}{
		{
			args:   Arguments{"foo", "bar"},
			has:    []string{"foo", "bar"},
			expect: true,
		},
		{
			args:   Arguments{"foo", "bar"},
			has:    []string{"bar", "foo"},
			expect: true,
		},
		{
			args:   Arguments{"bar", "foo"},
			has:    []string{"foo"},
			expect: true,
		},
		{
			args:   Arguments{"foo", "bar"},
			has:    []string{"bar", "foo", "baz"},
			expect: false,
		},
		{
			args:   Arguments{"foo", "bar"},
			has:    []string{"foo"},
			expect: true,
		},
		{
			args:   Arguments{"foo", "bar"},
			has:    []string{"bar"},
			expect: true,
		},
		{
			args:   Arguments{"foo", "bar"},
			has:    []string{"baz"},
			expect: false,
		},
		{
			args:   Arguments{},
			has:    []string{"baz"},
			expect: false,
		},
	} {
		assert.Equal(t, c.expect, c.args.Has(c.has...), "%d", k)
		t.Logf("Passed test case %d", k)
	}
}

func TestArgumentsMatches(t *testing.T) {
	for k, c := range []struct {
		args   Arguments
		is     []string
		expect bool
	}{
		{
			args:   Arguments{"foo", "bar"},
			is:     []string{"foo", "bar"},
			expect: true,
		},
		{
			args:   Arguments{"foo", "foo"},
			is:     []string{"foo"},
			expect: false,
		},
		{
			args:   Arguments{"foo", "foo"},
			is:     []string{"bar", "foo"},
			expect: false,
		},
		{
			args:   Arguments{"foo", "bar"},
			is:     []string{"bar", "foo", "baz"},
			expect: false,
		},
		{
			args:   Arguments{"foo", "bar"},
			is:     []string{"foo"},
			expect: false,
		},
		{
			args:   Arguments{"foo", "bar"},
			is:     []string{"bar", "bar"},
			expect: false,
		},
		{
			args:   Arguments{"foo", "bar"},
			is:     []string{"baz"},
			expect: false,
		},
		{
			args:   Arguments{},
			is:     []string{"baz"},
			expect: false,
		},
	} {
		assert.Equal(t, c.expect, c.args.Matches(c.is...), "%d", k)
		t.Logf("Passed test case %d", k)
	}
}

func TestArgumentsOneOf(t *testing.T) {
	for k, c := range []struct {
		args   Arguments
		oneOf  []string
		expect bool
	}{
		{
			args:   Arguments{"baz", "bar"},
			oneOf:  []string{"foo", "bar"},
			expect: true,
		},
		{
			args:   Arguments{"foo", "baz"},
			oneOf:  []string{"foo", "bar"},
			expect: true,
		},
		{
			args:   Arguments{"baz"},
			oneOf:  []string{"foo", "bar"},
			expect: false,
		},
	} {
		assert.Equal(t, c.expect, c.args.HasOneOf(c.oneOf...), "%d", k)
		t.Logf("Passed test case %d", k)
	}
}
