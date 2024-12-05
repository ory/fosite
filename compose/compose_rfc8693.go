// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/rfc8693"
	"github.com/ory/fosite/token/jwt"
)

// RFC8693AccessTokenTypeHandlerFactory creates a access token type handler.
func RFC8693AccessTokenTypeHandlerFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc8693.AccessTokenTypeHandler{
		CoreStrategy: strategy.(oauth2.CoreStrategy),
		Storage:      storage.(rfc8693.Storage),
		Config:       config,
	}
}

// RFC8693RefreshTokenTypeHandlerFactory creates a refresh token type handler.
func RFC8693RefreshTokenTypeHandlerFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc8693.RefreshTokenTypeHandler{
		CoreStrategy: strategy.(oauth2.CoreStrategy),
		Storage:      storage.(rfc8693.Storage),
		Config:       config,
	}
}

// RFC8693ActorTokenValidationHandlerFactory creates a actor token validation handler.
func RFC8693ActorTokenValidationHandlerFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc8693.ActorTokenValidationHandler{}
}

// RFC8693CustomJWTTypeHandlerFactory creates a custom JWT token type handler.
func RFC8693CustomJWTTypeHandlerFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc8693.CustomJWTTypeHandler{
		JWTStrategy: strategy.(jwt.Signer),
		Storage:     storage.(rfc8693.Storage),
		Config:      config,
	}
}

// RFC8693TokenExchangeGrantHandlerFactory creates the request validation handler for token exchange. This should be the first
// in the list.
func RFC8693TokenExchangeGrantHandlerFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc8693.TokenExchangeGrantHandler{
		Config: config,
	}
}

// RFC8693IDTokenTypeHandlerFactory creates a ID token type handler.
func RFC8693IDTokenTypeHandlerFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc8693.IDTokenTypeHandler{
		JWTStrategy:        strategy.(jwt.Signer),
		Storage:            storage.(rfc8693.Storage),
		Config:             config,
		IssueStrategy:      strategy.(openid.OpenIDConnectTokenStrategy),
		ValidationStrategy: strategy.(openid.OpenIDConnectTokenValidationStrategy),
	}
}
