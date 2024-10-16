// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package verifiable

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func GenerateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("unable to generate nonce")
	}

	return base64.RawURLEncoding.EncodeToString(nonceBytes), nil
}
