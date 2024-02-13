// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/verifiable"
)

// OIDCUserinfoVerifiableCredentialFactory creates a verifiable credentials
// handler.
func OIDCUserinfoVerifiableCredentialFactory(config fosite.Configurator, storage, strategy any) any {
	return &verifiable.Handler{
		NonceManager: storage.(verifiable.NonceManager),
		Config:       config,
	}
}
