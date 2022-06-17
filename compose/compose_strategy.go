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

package compose

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/hmac"
	"github.com/ory/fosite/token/jwt"
)

type CommonStrategy struct {
	oauth2.CoreStrategy
	openid.OpenIDConnectTokenStrategy
	jwt.Signer
}

type HMACSHAStrategyConfigurator interface {
	fosite.AccessTokenLifespanProvider
	fosite.RefreshTokenLifespanProvider
	fosite.AuthorizeCodeLifespanProvider
	fosite.TokenEntropyProvider
	fosite.GlobalSecretProvider
	fosite.RotatedGlobalSecretsProvider
	fosite.HMACHashingProvider
}

func NewOAuth2HMACStrategy(config HMACSHAStrategyConfigurator) *oauth2.HMACSHAStrategy {
	return &oauth2.HMACSHAStrategy{
		Enigma: &hmac.HMACStrategy{Config: config},
		Config: config,
	}
}

func NewOAuth2JWTStrategy(keyGetter func(context.Context) (interface{}, error), strategy *oauth2.HMACSHAStrategy, config fosite.Configurator) *oauth2.DefaultJWTStrategy {
	return &oauth2.DefaultJWTStrategy{
		Signer:          &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		HMACSHAStrategy: strategy,
		Config:          config,
	}
}

func NewOpenIDConnectStrategy(keyGetter func(context.Context) (interface{}, error), config fosite.Configurator) *openid.DefaultStrategy {
	return &openid.DefaultStrategy{
		Signer: &jwt.DefaultSigner{GetPrivateKey: keyGetter},
		Config: config,
	}
}
