// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/rfc8628"
	"github.com/ory/fosite/token/hmac"
	"github.com/ory/fosite/token/jwt"
)

type CommonStrategy struct {
	coreStrategy               *oauth2.HMACSHAStrategy
	rfc8628CodeStrategy        *rfc8628.DefaultDeviceStrategy
	openIDConnectTokenStrategy *openid.DefaultStrategy
	jwt.Signer
}

// OAuth2 Strategy Providers
func (s *CommonStrategy) AuthorizeCodeStrategy() oauth2.AuthorizeCodeStrategy {
	return s.coreStrategy
}

func (s *CommonStrategy) AccessTokenStrategy() oauth2.AccessTokenStrategy {
	return s.coreStrategy
}

func (s *CommonStrategy) RefreshTokenStrategy() oauth2.RefreshTokenStrategy {
	return s.coreStrategy
}

// OpenID Strategy Provider
func (s *CommonStrategy) OpenIDConnectTokenStrategy() openid.OpenIDConnectTokenStrategy {
	return s.openIDConnectTokenStrategy
}

// RFC8628 Device Strategy Providers
func (s *CommonStrategy) DeviceRateLimitStrategy() rfc8628.DeviceRateLimitStrategy {
	return s.rfc8628CodeStrategy
}

func (s *CommonStrategy) DeviceCodeStrategy() rfc8628.DeviceCodeStrategy {
	return s.rfc8628CodeStrategy
}

func (s *CommonStrategy) UserCodeStrategy() rfc8628.UserCodeStrategy {
	return s.rfc8628CodeStrategy
}

type HMACSHAStrategyConfigurator interface {
	fosite.AccessTokenLifespanProvider
	fosite.RefreshTokenLifespanProvider
	fosite.AuthorizeCodeLifespanProvider
	fosite.TokenEntropyProvider
	fosite.GlobalSecretProvider
	fosite.RotatedGlobalSecretsProvider
	fosite.HMACHashingProvider
	fosite.DeviceAndUserCodeLifespanProvider
}

func NewOAuth2HMACStrategy(config HMACSHAStrategyConfigurator) *oauth2.HMACSHAStrategy {
	return oauth2.NewHMACSHAStrategy(&hmac.HMACStrategy{Config: config}, config)
}

func NewOAuth2JWTStrategy(keyGetter func(context.Context) (interface{}, error), strategy interface{}, config fosite.Configurator) *oauth2.DefaultJWTStrategy {
	return &oauth2.DefaultJWTStrategy{
		Signer: &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		Strategy: strategy.(interface {
			oauth2.AuthorizeCodeStrategyProvider
			oauth2.RefreshTokenStrategyProvider
		}),
		Config: config,
	}
}

func NewOpenIDConnectStrategy(keyGetter func(context.Context) (interface{}, error), config fosite.Configurator) *openid.DefaultStrategy {
	return &openid.DefaultStrategy{
		Signer: &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		Config: config,
	}
}

// Create a new device strategy
func NewDeviceStrategy(config fosite.Configurator) *rfc8628.DefaultDeviceStrategy {
	return &rfc8628.DefaultDeviceStrategy{
		Enigma: &hmac.HMACStrategy{Config: config},
		Config: config,
	}
}
