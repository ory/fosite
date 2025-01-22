// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

type Factory func(config fosite.Configurator, storage interface{}, strategy interface{}) interface{}

// Compose takes a config, a storage, a strategy and handlers to instantiate an OAuth2Provider:
//
//	 import "github.com/ory/fosite/compose"
//
//	 // var storage = new(MyFositeStorage)
//	 var config = Config {
//	 	AccessTokenLifespan: time.Minute * 30,
//			// check Config for further configuration options
//	 }
//
//	 var strategy = NewOAuth2HMACStrategy(config)
//
//	 var oauth2Provider = Compose(
//	 	config,
//			storage,
//			strategy,
//			NewOAuth2AuthorizeExplicitHandler,
//			OAuth2ClientCredentialsGrantFactory,
//			// for a complete list refer to the docs of this package
//	 )
//
// Compose makes use of interface{} types in order to be able to handle a all types of stores, strategies and handlers.
func Compose(config *fosite.Config, storage interface{}, strategy interface{}, factories ...Factory) fosite.OAuth2Provider {
	f := fosite.NewOAuth2Provider(storage.(fosite.Storage), config)
	for _, factory := range factories {
		res := factory(config, storage, strategy)
		if ah, ok := res.(fosite.AuthorizeEndpointHandler); ok {
			config.AuthorizeEndpointHandlers.Append(ah)
		}
		if th, ok := res.(fosite.TokenEndpointHandler); ok {
			config.TokenEndpointHandlers.Append(th)
		}
		if tv, ok := res.(fosite.TokenIntrospector); ok {
			config.TokenIntrospectionHandlers.Append(tv)
		}
		if rh, ok := res.(fosite.RevocationHandler); ok {
			config.RevocationHandlers.Append(rh)
		}
		if ph, ok := res.(fosite.PushedAuthorizeEndpointHandler); ok {
			config.PushedAuthorizeEndpointHandlers.Append(ph)
		}
		if dh, ok := res.(fosite.DeviceEndpointHandler); ok {
			config.DeviceEndpointHandlers.Append(dh)
		}
	}

	return f
}

// ComposeAllEnabled returns a fosite instance with all OAuth2 and OpenID Connect handlers enabled.
func ComposeAllEnabled(config *fosite.Config, storage interface{}, key interface{}) fosite.OAuth2Provider {
	keyGetter := func(context.Context) (interface{}, error) {
		return key, nil
	}
	return Compose(
		config,
		storage,
		&CommonStrategy{
			CoreStrategy:               NewOAuth2HMACStrategy(config),
			RFC8628CodeStrategy:        NewDeviceStrategy(config),
			OpenIDConnectTokenStrategy: NewOpenIDConnectStrategy(keyGetter, config),
			Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		},
		OAuth2AuthorizeExplicitAuthFactory,
		Oauth2AuthorizeExplicitTokenFactory,
		OAuth2AuthorizeImplicitFactory,
		OAuth2ClientCredentialsGrantFactory,
		OAuth2RefreshTokenGrantFactory,
		OAuth2ResourceOwnerPasswordCredentialsFactory,
		RFC7523AssertionGrantFactory,

		OpenIDConnectExplicitFactory,
		OpenIDConnectImplicitFactory,
		OpenIDConnectHybridFactory,
		OpenIDConnectRefreshFactory,

		OAuth2TokenIntrospectionFactory,
		OAuth2TokenRevocationFactory,

		RFC8628DeviceFactory,
		RFC8628DeviceAuthorizationTokenFactory,

		OAuth2PKCEFactory,
		PushedAuthorizeHandlerFactory,
	)
}
