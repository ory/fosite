// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
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

// PreAuthorizeCodeTokenHandlerFactory creates handler for pre-authorize code flow at token endpoint
func PreAuthorizeCodeTokenHandlerFactory(config fosite.Configurator, storage, strategy interface{}) interface{} {
	return &verifiable.PreAuthorizeCodeTokenHandler{
		AuthorizeCodeStrategy:  strategy.(oauth2.AuthorizeCodeStrategy),
		AccessTokenStrategy:    strategy.(oauth2.AccessTokenStrategy),
		RefreshTokenStrategy:   strategy.(oauth2.RefreshTokenStrategy),
		TokenRevocationStorage: storage.(oauth2.TokenRevocationStorage),
		Storage:                storage.(verifiable.Storage),
		Config:                 config,
	}
}

// CredentialNonceHandlerFactory creates handler to generate credential nonce at token endpoint
func CredentialNonceHandlerFactory(config fosite.Configurator, storage, strategy interface{}) interface{} {
	return &verifiable.CredentialNonceHandler{
		Config: config,
	}
}

// IssuerStateHandlerFactory creates handler for issuer_state at authorize endpoint
func IssuerStateHandlerFactory(config fosite.Configurator, storage, strategy interface{}) interface{} {
	return &verifiable.IssuerStateHandler{}
}
