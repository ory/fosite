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

package hmac

import (
	"testing"

	"github.com/ory/fosite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateFailsWithShortCredentials(t *testing.T) {
	cg := HMACStrategy{GlobalSecret: []byte("foo")}
	challenge, signature, err := cg.Generate()
	require.Error(t, err)
	require.Empty(t, challenge)
	require.Empty(t, signature)
}

func TestGenerate(t *testing.T) {
	for _, c := range []struct {
		globalSecret []byte
		tokenEntropy int
	}{
		{
			globalSecret: []byte("1234567890123456789012345678901234567890"),
			tokenEntropy: 32,
		},
		{
			globalSecret: []byte("1234567890123456789012345678901234567890"),
			tokenEntropy: 64,
		},
	} {
		cg := HMACStrategy{
			GlobalSecret: c.globalSecret,
			TokenEntropy: c.tokenEntropy,
		}

		token, signature, err := cg.Generate()
		require.NoError(t, err)
		require.NotEmpty(t, token)
		require.NotEmpty(t, signature)
		t.Logf("Token: %s\n Signature: %s", token, signature)

		err = cg.Validate(token)
		require.NoError(t, err)

		validateSignature := cg.Signature(token)
		assert.Equal(t, signature, validateSignature)

		cg.GlobalSecret = []byte("baz")
		err = cg.Validate(token)
		require.Error(t, err)
	}
}

func TestValidateSignatureRejects(t *testing.T) {
	var err error
	cg := HMACStrategy{
		GlobalSecret: []byte("1234567890123456789012345678901234567890"),
	}
	for k, c := range []string{
		"",
		" ",
		"foo.bar",
		"foo.",
		".foo",
	} {
		err = cg.Validate(c)
		assert.Error(t, err)
		t.Logf("Passed test case %d", k)
	}
}

func TestValidateWithRotatedKey(t *testing.T) {
	old := HMACStrategy{
		GlobalSecret: []byte("1234567890123456789012345678901234567890"),
	}
	now := HMACStrategy{
		GlobalSecret: []byte("0000000090123456789012345678901234567890"),
		RotatedGlobalSecrets: [][]byte{
			[]byte("abcdefgh90123456789012345678901234567890"),
			[]byte("1234567890123456789012345678901234567890"),
		},
	}

	token, _, err := old.Generate()
	require.NoError(t, err)

	require.EqualError(t, now.Validate("thisisatoken.withaninvalidsignature"), fosite.ErrTokenSignatureMismatch.Error())
	require.NoError(t, now.Validate(token))
}

func TestValidateWithRotatedKeyInvalid(t *testing.T) {
	old := HMACStrategy{
		GlobalSecret: []byte("1234567890123456789012345678901234567890"),
	}
	now := HMACStrategy{
		GlobalSecret: []byte("0000000090123456789012345678901234567890"),
		RotatedGlobalSecrets: [][]byte{
			[]byte("abcdefgh90123456789012345678901"),
			[]byte("1234567890123456789012345678901234567890"),
		},
	}

	token, _, err := old.Generate()
	require.NoError(t, err)

	require.EqualError(t, now.Validate(token), "secret for signing HMAC-SHA512/256 is expected to be 32 byte long, got 31 byte")

	require.EqualError(t, new(HMACStrategy).Validate(token), "a secret for signing HMAC-SHA512/256 is expected to be defined, but none were")
}

func TestRotate(t *testing.T) {
	for _, test := range []struct {
		Name                         string
		GloabSecret                  []byte
		RotatedGlobalSecrets         [][]byte
		NewSecret                    []byte
		ExpectedGloabSecret          []byte
		ExpectedRotatedGlobalSecrets [][]byte
	}{
		{
			Name:                         "Nil Rotated Secrets",
			GloabSecret:                  []byte("1234567890123456789012345678901234567890"),
			RotatedGlobalSecrets:         nil,
			NewSecret:                    []byte("0000000090123456789012345678901234567890"),
			ExpectedGloabSecret:          []byte("0000000090123456789012345678901234567890"),
			ExpectedRotatedGlobalSecrets: [][]byte{[]byte("1234567890123456789012345678901234567890")},
		},
		{
			Name:                         "Existing Rotated Secret",
			GloabSecret:                  []byte("1234567890123456789012345678901234567890"),
			RotatedGlobalSecrets:         [][]byte{[]byte("abcdefgh90123456789012345678901")},
			NewSecret:                    []byte("0000000090123456789012345678901234567890"),
			ExpectedGloabSecret:          []byte("0000000090123456789012345678901234567890"),
			ExpectedRotatedGlobalSecrets: [][]byte{[]byte("abcdefgh90123456789012345678901"), []byte("1234567890123456789012345678901234567890")},
		},
	} {
		t.Run(test.Name, func(t *testing.T) {
			// create initial strategy
			strategy := HMACStrategy{
				GlobalSecret:         test.GloabSecret,
				RotatedGlobalSecrets: test.RotatedGlobalSecrets,
			}

			// rotate the key
			strategy.Rotate(test.NewSecret)

			// validate
			require.Equal(t, test.ExpectedGloabSecret, strategy.GlobalSecret, "ExpectedGlobalSecret does match provided GlobalSecret")
			require.Equal(t, test.ExpectedRotatedGlobalSecrets, strategy.RotatedGlobalSecrets, "ExpectedRotatedGlobalSecrets does match provided RotatedGlobalSecrets")
		})
	}
}
