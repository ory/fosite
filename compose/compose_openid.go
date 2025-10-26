// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/rfc8628"
	"github.com/ory/fosite/token/jwt"
)

// OpenIDConnectExplicitFactory creates an OpenID Connect explicit ("authorize code flow") grant handler.
//
// **Important note:** You must add this handler *after* you have added an OAuth2 authorize code handler!
func OpenIDConnectExplicitFactory(config fosite.Configurator, storage fosite.Storage, strategy interface{}) interface{} {
	return &openid.ExplicitHandler{
		Storage: storage.(openid.OIDCRequestStorageProvider),
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
		},
		OpenIDConnectRequestValidator: openid.NewOpenIDConnectRequestValidator(strategy.(jwt.Signer), config),
		Config:                        config,
	}
}

// OpenIDConnectRefreshFactory creates a handler for refreshing openid connect tokens.
//
// **Important note:** You must add this handler *after* you have added an OAuth2 authorize code handler!
func OpenIDConnectRefreshFactory(config fosite.Configurator, _ fosite.Storage, strategy interface{}) interface{} {
	return &openid.OpenIDConnectRefreshHandler{
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
		},
		Config: config,
	}
}

// OpenIDConnectImplicitFactory creates an OpenID Connect implicit ("implicit flow") grant handler.
//
// **Important note:** You must add this handler *after* you have added an OAuth2 authorize code handler!
func OpenIDConnectImplicitFactory(config fosite.Configurator, storage fosite.Storage, strategy interface{}) interface{} {
	return &openid.OpenIDConnectImplicitHandler{
		AuthorizeImplicitGrantTypeHandler: &oauth2.AuthorizeImplicitGrantTypeHandler{
			AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(oauth2.AccessTokenStorageProvider),
			Config:              config,
		},
		Config: config,
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
		},
		OpenIDConnectRequestValidator: openid.NewOpenIDConnectRequestValidator(strategy.(jwt.Signer), config),
	}
}

// OpenIDConnectHybridFactory creates an OpenID Connect hybrid grant handler.
//
// **Important note:** You must add this handler *after* you have added an OAuth2 authorize code handler!
func OpenIDConnectHybridFactory(config fosite.Configurator, storage fosite.Storage, strategy interface{}) interface{} {
	return &openid.OpenIDConnectHybridHandler{
		AuthorizeExplicitGrantHandler: &oauth2.AuthorizeExplicitGrantHandler{
			AccessTokenStrategy:   strategy.(oauth2.AccessTokenStrategy),
			RefreshTokenStrategy:  strategy.(oauth2.RefreshTokenStrategy),
			AuthorizeCodeStrategy: strategy.(oauth2.AuthorizeCodeStrategy),
			Storage:               storage.(oauth2.CoreStorage),
			Config:                config,
		},
		Config: config,
		AuthorizeImplicitGrantTypeHandler: &oauth2.AuthorizeImplicitGrantTypeHandler{
			AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(oauth2.AccessTokenStorageProvider),
			Config:              config,
		},
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
		},
		OpenIDConnectRequestStorage:   storage.(openid.OIDCRequestStorageProvider),
		OpenIDConnectRequestValidator: openid.NewOpenIDConnectRequestValidator(strategy.(jwt.Signer), config),
	}
}

// OpenIDConnectDeviceFactory creates an OpenID Connect device ("device code flow") grant handler.
//
// **Important note:** You must add this handler *after* you have added an OAuth2 device authorization handler!
func OpenIDConnectDeviceFactory(config fosite.Configurator, storage fosite.Storage, strategy interface{}) interface{} {
	return &openid.OpenIDConnectDeviceHandler{
		OpenIDConnectRequestStorage: storage.(openid.OIDCRequestStorageProvider),
		IDTokenHandleHelper: &openid.IDTokenHandleHelper{
			IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
		},
		DeviceCodeStrategy: strategy.(rfc8628.DeviceCodeStrategy),
		Config:             config,
	}
}
