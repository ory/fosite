// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "github.com/ory/fosite/token/jwt"
)

func TestIDTokenAssert(t *testing.T) {
	assert.NoError(t, (&IDTokenClaims{ExpiresAt: time.Now().UTC().Add(time.Hour)}).
		ToMapClaims().Valid())
	assert.Error(t, (&IDTokenClaims{ExpiresAt: time.Now().UTC().Add(-time.Hour)}).
		ToMapClaims().Valid())

	assert.NotEmpty(t, (new(IDTokenClaims)).ToMapClaims()["jti"])
}

func TestIDTokenClaimsToMap(t *testing.T) {
	idTokenClaims := &IDTokenClaims{
		JTI:                                 "foo-id",
		Subject:                             "peter",
		IssuedAt:                            time.Now().UTC().Round(time.Second),
		Issuer:                              "fosite",
		Audience:                            []string{"tests"},
		ExpiresAt:                           time.Now().UTC().Add(time.Hour).Round(time.Second),
		AuthTime:                            time.Now().UTC(),
		RequestedAt:                         time.Now().UTC(),
		AccessTokenHash:                     "foobar",
		CodeHash:                            "barfoo",
		AuthenticationContextClassReference: "acr",
		AuthenticationMethodsReferences:     []string{"amr"},
		Extra: map[string]interface{}{
			"foo": "bar",
			"baz": "bar",
		},
	}
	assert.Equal(t, map[string]interface{}{
		"jti":       idTokenClaims.JTI,
		"sub":       idTokenClaims.Subject,
		"iat":       idTokenClaims.IssuedAt.Unix(),
		"rat":       idTokenClaims.RequestedAt.Unix(),
		"iss":       idTokenClaims.Issuer,
		"aud":       idTokenClaims.Audience,
		"exp":       idTokenClaims.ExpiresAt.Unix(),
		"foo":       idTokenClaims.Extra["foo"],
		"baz":       idTokenClaims.Extra["baz"],
		"at_hash":   idTokenClaims.AccessTokenHash,
		"c_hash":    idTokenClaims.CodeHash,
		"auth_time": idTokenClaims.AuthTime.Unix(),
		"acr":       idTokenClaims.AuthenticationContextClassReference,
		"amr":       idTokenClaims.AuthenticationMethodsReferences,
	}, idTokenClaims.ToMap())

	idTokenClaims.Nonce = "foobar"
	assert.Equal(t, map[string]interface{}{
		"jti":       idTokenClaims.JTI,
		"sub":       idTokenClaims.Subject,
		"iat":       idTokenClaims.IssuedAt.Unix(),
		"rat":       idTokenClaims.RequestedAt.Unix(),
		"iss":       idTokenClaims.Issuer,
		"aud":       idTokenClaims.Audience,
		"exp":       idTokenClaims.ExpiresAt.Unix(),
		"foo":       idTokenClaims.Extra["foo"],
		"baz":       idTokenClaims.Extra["baz"],
		"at_hash":   idTokenClaims.AccessTokenHash,
		"c_hash":    idTokenClaims.CodeHash,
		"auth_time": idTokenClaims.AuthTime.Unix(),
		"acr":       idTokenClaims.AuthenticationContextClassReference,
		"amr":       idTokenClaims.AuthenticationMethodsReferences,
		"nonce":     idTokenClaims.Nonce,
	}, idTokenClaims.ToMap())
}

func TestIDTokenClaimsToMap_new_aud(t *testing.T) {
	// extra & overlap
	IDClaims := &IDTokenClaims{
		JTI:      "foo-id",
		Audience: []string{"default"},
		Extra: map[string]any{
			"aud": []string{"default", "new"},
		},
	}
	assert.Equal(t, map[string]any{
		"jti": "foo-id",
		"aud": []string{"default", "new"},
	}, IDClaims.ToMap())

	// extra & no original values
	IDClaims = &IDTokenClaims{
		JTI: "foo-id",
		Extra: map[string]any{
			"aud": []string{"default", "new"},
		},
	}
	assert.Equal(t, map[string]any{
		"jti": "foo-id",
		"aud": []string{"default", "new"},
	}, IDClaims.ToMap())

	// only original values
	IDClaims = &IDTokenClaims{
		JTI:      "foo-id",
		Audience: []string{"default"},
	}
	assert.Equal(t, map[string]any{
		"jti": "foo-id",
		"aud": []string{"default"},
	}, IDClaims.ToMap())

	// extra value is an string
	IDClaims = &IDTokenClaims{
		JTI:      "foo-id",
		Audience: []string{"default"},
		Extra: map[string]any{
			"aud": "new",
		},
	}
	assert.Equal(t, map[string]any{
		"jti": "foo-id",
		"aud": []string{"default", "new"},
	}, IDClaims.ToMap())
}
