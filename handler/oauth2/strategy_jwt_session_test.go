// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestJWTSession_GetJWTHeader(t *testing.T) {
	testCases := []struct {
		name     string
		have     *JWTSession
		expected string
	}{
		{
			"ShouldReturnDefaultTyp",
			&JWTSession{},
			"at+jwt",
		},
		{
			"ShouldReturnConfiguredATJWTTyp",
			&JWTSession{JWTHeader: &jwt.Headers{Extra: map[string]interface{}{
				"typ": "at+jwt",
			}}},
			"at+jwt",
		},
		{
			"ShouldReturnConfiguredJWTTyp",
			&JWTSession{JWTHeader: &jwt.Headers{Extra: map[string]interface{}{
				"typ": "JWT",
			}}},
			"JWT",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			header := tc.have.GetJWTHeader()

			assert.Equal(t, tc.expected, header.Get("typ"))
		})
	}
}
