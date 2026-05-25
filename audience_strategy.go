// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/ory/x/errorsx"
)

type AudienceMatchingStrategy func(haystack []string, needle []string) error

func DefaultAudienceMatchingStrategy(haystack []string, needle []string) error {
	if len(needle) == 0 {
		return nil
	}

	for _, n := range needle {
		nu, err := url.Parse(n)
		if err != nil {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf("Unable to parse requested audience '%s'.", n).WithWrap(err).WithDebug(err.Error()))
		}

		var found bool
		for _, h := range haystack {
			hu, err := url.Parse(h)
			if err != nil {
				return errorsx.WithStack(ErrInvalidRequest.WithHintf("Unable to parse whitelisted audience '%s'.", h).WithWrap(err).WithDebug(err.Error()))
			}

			allowedPath := strings.TrimRight(hu.Path, "/")
			if nu.Scheme == hu.Scheme &&
				nu.Host == hu.Host &&
				(nu.Path == hu.Path ||
					nu.Path == allowedPath ||
					len(nu.Path) > len(allowedPath) && strings.TrimRight(nu.Path[:len(allowedPath)+1], "/")+"/" == allowedPath+"/") {
				found = true
			}
		}

		if !found {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf("Requested audience '%s' has not been whitelisted by the OAuth 2.0 Client.", n))
		}
	}

	return nil
}

// ExactAudienceMatchingStrategy does not assume that audiences are URIs, but compares strings as-is and
// does matching with exact string comparison. It requires that all strings in "needle" are present in
// "haystack". Use this strategy when your audience values are not URIs (e.g., you use client IDs for
// audience and they are UUIDs or random strings).
func ExactAudienceMatchingStrategy(haystack []string, needle []string) error {
	if len(needle) == 0 {
		return nil
	}

	for _, n := range needle {
		var found bool
		for _, h := range haystack {
			if n == h {
				found = true
			}
		}

		if !found {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf(`Requested audience "%s" has not been whitelisted by the OAuth 2.0 Client.`, n))
		}
	}

	return nil
}

// GetAudiences allows audiences to be provided as repeated "audience" form parameter,
// or as a space-delimited "audience" form parameter if it is not repeated.
// RFC 8693 in section 2.1 specifies that multiple audience values should be multiple
// query parameters, while RFC 6749 says that that request parameter must not be included
// more than once (and thus why we use space-delimited value). This function tries to satisfy both.
// If "audience" form parameter is repeated, we do not split the value by space.
//
// In addition, this function reads the RFC 8707 "resource" parameter
// (https://datatracker.ietf.org/doc/html/rfc8707#section-2). Per the spec, "resource"
// is a repeatable parameter; each value is treated as an audience indicator and is
// merged with any values supplied through the "audience" parameter. Unlike "audience",
// the "resource" parameter values are NOT space-split — RFC 8707 mandates one URI per
// parameter occurrence. Duplicate values across "audience" and "resource" are
// de-duplicated while preserving the order of first appearance ("audience" values
// first, then "resource" values).
//
// Note: this function does not validate that "resource" values are absolute URIs
// without a fragment as required by RFC 8707 §2 — that validation is performed by
// ValidateResourceIndicators, which callers invoke after parsing.
func GetAudiences(form url.Values) []string {
	var audiences []string
	formAudiences := form["audience"]
	if len(formAudiences) > 1 {
		audiences = RemoveEmpty(formAudiences)
	} else if len(formAudiences) == 1 {
		audiences = RemoveEmpty(strings.Split(formAudiences[0], " "))
	}

	resources := RemoveEmpty(form["resource"])
	if len(resources) == 0 {
		if audiences == nil {
			return []string{}
		}
		return audiences
	}

	// Merge audience and resource values, preserving order and de-duplicating.
	seen := make(map[string]struct{}, len(audiences)+len(resources))
	merged := make([]string, 0, len(audiences)+len(resources))
	for _, v := range audiences {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		merged = append(merged, v)
	}
	for _, v := range resources {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		merged = append(merged, v)
	}
	return merged
}

// ValidateResourceIndicators validates that every value of the RFC 8707 "resource"
// form parameter is an absolute URI without a fragment, as required by RFC 8707 §2:
//
//	The "resource" parameter URI value MUST NOT include a fragment component.
//	... It MUST be an absolute URI as specified by Section 4.3 of [RFC3986].
//
// On success the validated resource values are returned. If the form contains no
// "resource" parameter, the function returns (nil, nil) — RFC 8707 is opt-in.
//
// Callers (e.g. the access and authorize request pipelines) should invoke this
// function after parsing the form and reject the request with ErrInvalidTarget
// (RFC 8707 §3, the "invalid_target" error code) when validation fails. Because
// fosite does not yet ship a dedicated "invalid_target" error, ErrInvalidRequest
// is the closest fit in current callers; this function returns a plain error so
// the caller can wrap it appropriately.
func ValidateResourceIndicators(form url.Values) ([]string, error) {
	resources, ok := form["resource"]
	if !ok {
		return nil, nil
	}
	resources = RemoveEmpty(resources)
	if len(resources) == 0 {
		return nil, nil
	}

	for _, r := range resources {
		u, err := url.Parse(r)
		if err != nil {
			return nil, errorsx.WithStack(ErrInvalidRequest.
				WithHintf("Unable to parse 'resource' parameter value '%s'.", r).
				WithWrap(err).WithDebug(err.Error()))
		}
		if !u.IsAbs() {
			return nil, errorsx.WithStack(ErrInvalidRequest.
				WithHintf("The 'resource' parameter value '%s' must be an absolute URI as per RFC 8707.", r))
		}
		if u.Fragment != "" || strings.Contains(r, "#") {
			return nil, errorsx.WithStack(ErrInvalidRequest.
				WithHintf("The 'resource' parameter value '%s' must not contain a fragment component as per RFC 8707.", r))
		}
	}
	return resources, nil
}

func (f *Fosite) validateAudience(ctx context.Context, r *http.Request, request Requester) error {
	form := request.GetRequestForm()

	// RFC 8707: validate "resource" parameter shape (absolute URI, no fragment)
	// before merging into the audience list. Validation runs unconditionally — if
	// the parameter is absent, ValidateResourceIndicators is a no-op.
	if _, err := ValidateResourceIndicators(form); err != nil {
		return err
	}

	audience := GetAudiences(form)

	if err := f.Config.GetAudienceStrategy(ctx)(request.GetClient().GetAudience(), audience); err != nil {
		return err
	}

	request.SetRequestedAudience(audience)
	return nil
}
