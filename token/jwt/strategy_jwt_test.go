// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ory/fosite/internal/gen"
	"github.com/stretchr/testify/require"
)

func TestEncryptJWT(t *testing.T) {
	key := gen.MustRSAKey()
	encryptKey := gen.MustRSAKey()
	for k, tc := range []struct {
		d          string
		keyContext *KeyContext
		strategy   Strategy
		resetKey   func(strategy Strategy)
	}{
		{
			d: "SameKeyStrategy",
			keyContext: &KeyContext{
				EncryptionAlgorithm:        "RSA-OAEP",
				EncryptionContentAlgorithm: "A256GCM",
				EncryptionKeyID:            "samekey",
			},
			strategy: NewDefaultStrategy(func(_ context.Context, context *KeyContext) (interface{}, error) {
				return key, nil
			}),
			resetKey: func(strategy Strategy) {
				key = gen.MustRSAKey()
			},
		},
		{
			d: "EncryptionKeyStrategy",
			keyContext: &KeyContext{
				EncryptionAlgorithm:        "RSA-OAEP",
				EncryptionContentAlgorithm: "A256GCM",
				EncryptionKeyID:            "enc_key",
			},
			strategy: NewDefaultStrategy(func(_ context.Context, context *KeyContext) (interface{}, error) {
				if context == nil {
					return key, nil
				}

				if context.EncryptionKeyID == "enc_key" {
					return encryptKey, nil
				}

				return key, nil
			}),
			resetKey: func(strategy Strategy) {
				key = gen.MustRSAKey()
				encryptKey = gen.MustRSAKey()
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d/strategy=%s", k, tc.d), func(t *testing.T) {
			ctx := context.Background()

			// Reset private key
			tc.resetKey(tc.strategy)

			claims := &JWTClaims{
				ExpiresAt: time.Now().UTC().Add(time.Hour),
			}

			token, sig, err := tc.strategy.GenerateWithSettings(ctx, tc.keyContext, claims.ToMapClaims(), header)
			require.NoError(t, err)
			require.NotNil(t, token, "Token could not be generated")

			signedToken, err := tc.strategy.DecryptWithSettings(ctx, tc.keyContext, token)
			require.NoError(t, err)
			require.NotNil(t, signedToken, "Token could not be decrypted; token=%s", token)

			derivedSig, err := tc.strategy.Validate(ctx, signedToken)
			require.NoError(t, err)

			require.EqualValues(t, sig, derivedSig, "Signature does not match")
		})
	}
}
