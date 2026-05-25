// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultAudienceMatchingStrategy(t *testing.T) {
	for k, tc := range []struct {
		h   []string
		n   []string
		err bool
	}{
		{
			h:   []string{},
			n:   []string{},
			err: false,
		},
		{
			h:   []string{"http://foo/bar"},
			n:   []string{},
			err: false,
		},
		{
			h:   []string{},
			n:   []string{"http://foo/bar"},
			err: true,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"https://cloud.ory.sh/api/users"},
			err: false,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"https://cloud.ory.sh/api/users/"},
			err: false,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users/"},
			n:   []string{"https://cloud.ory.sh/api/users/"},
			err: false,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users/"},
			n:   []string{"https://cloud.ory.sh/api/users"},
			err: false,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"https://cloud.ory.sh/api/users/1234"},
			err: false,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"https://cloud.ory.sh/api/users", "https://cloud.ory.sh/api/users/", "https://cloud.ory.sh/api/users/1234"},
			err: false,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users", "https://cloud.ory.sh/api/tenants"},
			n:   []string{"https://cloud.ory.sh/api/users", "https://cloud.ory.sh/api/users/", "https://cloud.ory.sh/api/users/1234", "https://cloud.ory.sh/api/tenants"},
			err: false,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"https://cloud.ory.sh/api/users1234"},
			err: true,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"http://cloud.ory.sh/api/users"},
			err: true,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"https://cloud.ory.sh:8000/api/users"},
			err: true,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"https://cloud.ory.xyz/api/users"},
			err: true,
		},
		{
			h:   []string{"foobar"},
			n:   []string{"foobar"},
			err: false,
		},
		{
			h:   []string{"foo bar"},
			n:   []string{"foo bar"},
			err: false,
		},
		{
			h:   []string{"foobar"},
			n:   []string{"foobar"},
			err: false,
		},
		{
			h:   []string{"zoo", "bar"},
			n:   []string{"zoo"},
			err: false,
		},
		{
			h:   []string{"zoo"},
			n:   []string{"zoo", "bar"},
			err: true,
		},
		{
			h:   []string{"foobar"},
			n:   []string{"foobar/"},
			err: false,
		},
		{
			h:   []string{"foobar/"},
			n:   []string{"foobar"},
			err: false,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			err := DefaultAudienceMatchingStrategy(tc.h, tc.n)
			if tc.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestExactAudienceMatchingStrategy(t *testing.T) {
	for k, tc := range []struct {
		h   []string
		n   []string
		err bool
	}{
		{
			h:   []string{},
			n:   []string{},
			err: false,
		},
		{
			h:   []string{"http://foo/bar"},
			n:   []string{},
			err: false,
		},
		{
			h:   []string{},
			n:   []string{"http://foo/bar"},
			err: true,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"https://cloud.ory.sh/api/users"},
			err: false,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"https://cloud.ory.sh/api/users/"},
			err: true,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users/"},
			n:   []string{"https://cloud.ory.sh/api/users/"},
			err: false,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users/"},
			n:   []string{"https://cloud.ory.sh/api/users"},
			err: true,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"https://cloud.ory.sh/api/users/1234"},
			err: true,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"https://cloud.ory.sh/api/users", "https://cloud.ory.sh/api/users/", "https://cloud.ory.sh/api/users/1234"},
			err: true,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users", "https://cloud.ory.sh/api/tenants"},
			n:   []string{"https://cloud.ory.sh/api/users", "https://cloud.ory.sh/api/users/", "https://cloud.ory.sh/api/users/1234", "https://cloud.ory.sh/api/tenants"},
			err: true,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"https://cloud.ory.sh/api/users1234"},
			err: true,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"http://cloud.ory.sh/api/users"},
			err: true,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"https://cloud.ory.sh:8000/api/users"},
			err: true,
		},
		{
			h:   []string{"https://cloud.ory.sh/api/users"},
			n:   []string{"https://cloud.ory.xyz/api/users"},
			err: true,
		},
		{
			h:   []string{"foobar"},
			n:   []string{"foobar"},
			err: false,
		},
		{
			h:   []string{"foo bar"},
			n:   []string{"foo bar"},
			err: false,
		},
		{
			h:   []string{"foobar"},
			n:   []string{"foobar"},
			err: false,
		},
		{
			h:   []string{"zoo", "bar"},
			n:   []string{"zoo"},
			err: false,
		},
		{
			h:   []string{"zoo"},
			n:   []string{"zoo", "bar"},
			err: true,
		},
		{
			h:   []string{"foobar"},
			n:   []string{"foobar/"},
			err: true,
		},
		{
			h:   []string{"foobar/"},
			n:   []string{"foobar"},
			err: true,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			err := ExactAudienceMatchingStrategy(tc.h, tc.n)
			if tc.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetAudiences(t *testing.T) {
	for _, tc := range []struct {
		name string
		form url.Values
		want []string
	}{
		{
			name: "empty form returns empty slice",
			form: url.Values{},
			want: []string{},
		},
		// Existing "audience" parameter behavior — preserved.
		{
			name: "single audience parameter, space-delimited values are split",
			form: url.Values{"audience": {"https://a.example.com https://b.example.com"}},
			want: []string{"https://a.example.com", "https://b.example.com"},
		},
		{
			name: "repeated audience parameter, values not split on space",
			form: url.Values{"audience": {"https://a.example.com", "https://b.example.com"}},
			want: []string{"https://a.example.com", "https://b.example.com"},
		},
		// RFC 8707 "resource" parameter.
		{
			name: "single resource parameter is returned",
			form: url.Values{"resource": {"https://mcp.example.com"}},
			want: []string{"https://mcp.example.com"},
		},
		{
			name: "repeated resource parameter is returned, not split on space",
			form: url.Values{"resource": {"https://a.example.com", "https://b.example.com"}},
			want: []string{"https://a.example.com", "https://b.example.com"},
		},
		{
			name: "resource is not split on space (one URI per parameter occurrence per RFC 8707)",
			// "https://a https://b" is technically an invalid resource value per RFC 8707
			// (must be an absolute URI). GetAudiences does NOT validate — it just returns
			// the raw value verbatim so ValidateResourceIndicators can reject it.
			form: url.Values{"resource": {"https://a.example.com https://b.example.com"}},
			want: []string{"https://a.example.com https://b.example.com"},
		},
		{
			name: "audience and resource are merged, audience first",
			form: url.Values{
				"audience": {"https://aud.example.com"},
				"resource": {"https://res.example.com"},
			},
			want: []string{"https://aud.example.com", "https://res.example.com"},
		},
		{
			name: "duplicates across audience and resource are de-duplicated",
			form: url.Values{
				"audience": {"https://shared.example.com", "https://aud-only.example.com"},
				"resource": {"https://shared.example.com", "https://res-only.example.com"},
			},
			want: []string{"https://shared.example.com", "https://aud-only.example.com", "https://res-only.example.com"},
		},
		{
			name: "duplicates within resource are de-duplicated",
			form: url.Values{
				"resource": {"https://a.example.com", "https://a.example.com", "https://b.example.com"},
			},
			want: []string{"https://a.example.com", "https://b.example.com"},
		},
		{
			name: "empty resource value is filtered out",
			form: url.Values{
				"resource": {"", "https://a.example.com"},
			},
			want: []string{"https://a.example.com"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, GetAudiences(tc.form))
		})
	}
}

func TestValidateResourceIndicators(t *testing.T) {
	for _, tc := range []struct {
		name    string
		form    url.Values
		want    []string
		wantErr bool
	}{
		{
			name: "absent resource parameter is a no-op",
			form: url.Values{},
			want: nil,
		},
		{
			name: "empty resource value is a no-op",
			form: url.Values{"resource": {""}},
			want: nil,
		},
		{
			name: "single valid absolute URI",
			form: url.Values{"resource": {"https://mcp.example.com"}},
			want: []string{"https://mcp.example.com"},
		},
		{
			name: "multiple valid absolute URIs",
			form: url.Values{"resource": {"https://a.example.com", "https://b.example.com/api"}},
			want: []string{"https://a.example.com", "https://b.example.com/api"},
		},
		{
			name: "URN scheme is a valid absolute URI",
			form: url.Values{"resource": {"urn:example:resource"}},
			want: []string{"urn:example:resource"},
		},
		{
			name:    "relative URI is rejected",
			form:    url.Values{"resource": {"/api/v1"}},
			wantErr: true,
		},
		{
			name:    "missing scheme is rejected",
			form:    url.Values{"resource": {"mcp.example.com/api"}},
			wantErr: true,
		},
		{
			name:    "URI with fragment is rejected",
			form:    url.Values{"resource": {"https://mcp.example.com/api#section"}},
			wantErr: true,
		},
		{
			name:    "URI with empty fragment marker is rejected",
			form:    url.Values{"resource": {"https://mcp.example.com/api#"}},
			wantErr: true,
		},
		{
			name:    "one invalid value among many fails the whole batch",
			form:    url.Values{"resource": {"https://a.example.com", "not-a-uri"}},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateResourceIndicators(tc.form)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
