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
	"html/template"
	"net/url"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/i18n"
)

type Config struct {
	// AccessTokenLifespan sets how long an access token is going to be valid. Defaults to one hour.
	AccessTokenLifespan time.Duration

	// RefreshTokenLifespan sets how long a refresh token is going to be valid. Defaults to 30 days. Set to -1 for
	// refresh tokens that never expire.
	RefreshTokenLifespan time.Duration

	// AuthorizeCodeLifespan sets how long an authorize code is going to be valid. Defaults to fifteen minutes.
	AuthorizeCodeLifespan time.Duration

	// IDTokenLifespan sets the default id token lifetime. Defaults to one hour.
	IDTokenLifespan time.Duration

	// IDTokenIssuer sets the default issuer of the ID Token.
	IDTokenIssuer string

	// HashCost sets the cost of the password hashing cost. Defaults to 12.
	HashCost int

	// DisableRefreshTokenValidation sets the introspection endpoint to disable refresh token validation.
	DisableRefreshTokenValidation bool

	// SendDebugMessagesToClients if set to true, includes error debug messages in response payloads. Be aware that sensitive
	// data may be exposed, depending on your implementation of Fosite. Such sensitive data might include database error
	// codes or other information. Proceed with caution!
	SendDebugMessagesToClients bool

	// ScopeStrategy sets the scope strategy that should be supported, for example fosite.WildcardScopeStrategy.
	ScopeStrategy fosite.ScopeStrategy

	// AudienceMatchingStrategy sets the audience matching strategy that should be supported, defaults to fosite.DefaultsAudienceMatchingStrategy.
	AudienceMatchingStrategy fosite.AudienceMatchingStrategy

	// EnforcePKCE, if set to true, requires clients to perform authorize code flows with PKCE. Defaults to false.
	EnforcePKCE bool

	// EnforcePKCEForPublicClients requires only public clients to use PKCE with the authorize code flow. Defaults to false.
	EnforcePKCEForPublicClients bool

	// EnablePKCEPlainChallengeMethod sets whether or not to allow the plain challenge method (S256 should be used whenever possible, plain is really discouraged). Defaults to false.
	EnablePKCEPlainChallengeMethod bool

	// AllowedPromptValues sets which OpenID Connect prompt values the server supports. Defaults to []string{"login", "none", "consent", "select_account"}.
	AllowedPromptValues []string

	// TokenURL is the the URL of the Authorization Server's Token Endpoint. If the authorization server is intended
	// to be compatible with the private_key_jwt client authentication method (see http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth),
	// this value MUST be set.
	TokenURL string

	// JWKSFetcherStrategy is responsible for fetching JSON Web Keys from remote URLs. This is required when the private_key_jwt
	// client authentication method is used. Defaults to fosite.DefaultJWKSFetcherStrategy.
	JWKSFetcher fosite.JWKSFetcherStrategy

	// TokenEntropy indicates the entropy of the random string, used as the "message" part of the HMAC token.
	// Defaults to 32.
	TokenEntropy int

	// RedirectSecureChecker is a function that returns true if the provided URL can be securely used as a redirect URL.
	RedirectSecureChecker func(*url.URL) bool

	// RefreshTokenScopes defines which OAuth scopes will be given refresh tokens during the authorization code grant exchange. This defaults to "offline" and "offline_access". When set to an empty array, all exchanges will be given refresh tokens.
	RefreshTokenScopes []string

	// MinParameterEntropy controls the minimum size of state and nonce parameters. Defaults to fosite.MinParameterEntropy.
	MinParameterEntropy int

	// UseLegacyErrorFormat controls whether the legacy error format (with `error_debug`, `error_hint`, ...)
	// should be used or not.
	UseLegacyErrorFormat bool

	// GrantTypeJWTBearerCanSkipClientAuth indicates, if client authentication can be skipped, when using jwt as assertion.
	GrantTypeJWTBearerCanSkipClientAuth bool

	// GrantTypeJWTBearerIDOptional indicates, if jti (JWT ID) claim required or not in JWT.
	GrantTypeJWTBearerIDOptional bool

	// GrantTypeJWTBearerIssuedDateOptional indicates, if "iat" (issued at) claim required or not in JWT.
	GrantTypeJWTBearerIssuedDateOptional bool

	// GrantTypeJWTBearerMaxDuration sets the maximum time after JWT issued date, during which the JWT is considered valid.
	GrantTypeJWTBearerMaxDuration time.Duration

	// ClientAuthenticationStrategy indicates the Strategy to authenticate client requests
	ClientAuthenticationStrategy fosite.ClientAuthenticationStrategy

	// ResponseModeHandlerExtension provides a handler for custom response modes
	ResponseModeHandlerExtension fosite.ResponseModeHandler

	// MessageCatalog is the message bundle used for i18n
	MessageCatalog i18n.MessageCatalog

	// FormPostHTMLTemplate sets html template for rendering the authorization response when the request has response_mode=form_post.
	FormPostHTMLTemplate *template.Template
}

// GetScopeStrategy returns the scope strategy to be used. Defaults to glob scope strategy.
func (c *Config) GetScopeStrategy() fosite.ScopeStrategy {
	if c.ScopeStrategy == nil {
		c.ScopeStrategy = fosite.WildcardScopeStrategy
	}
	return c.ScopeStrategy
}

// GetAudienceStrategy returns the scope strategy to be used. Defaults to glob scope strategy.
func (c *Config) GetAudienceStrategy() fosite.AudienceMatchingStrategy {
	if c.AudienceMatchingStrategy == nil {
		c.AudienceMatchingStrategy = fosite.DefaultAudienceMatchingStrategy
	}
	return c.AudienceMatchingStrategy
}

// GetAuthorizeCodeLifespan returns how long an authorize code should be valid. Defaults to one fifteen minutes.
func (c *Config) GetAuthorizeCodeLifespan() time.Duration {
	if c.AuthorizeCodeLifespan == 0 {
		return time.Minute * 15
	}
	return c.AuthorizeCodeLifespan
}

// GeIDTokenLifespan returns how long an id token should be valid. Defaults to one hour.
func (c *Config) GetIDTokenLifespan() time.Duration {
	if c.IDTokenLifespan == 0 {
		return time.Hour
	}
	return c.IDTokenLifespan
}

// GetAccessTokenLifespan returns how long an access token should be valid. Defaults to one hour.
func (c *Config) GetAccessTokenLifespan() time.Duration {
	if c.AccessTokenLifespan == 0 {
		return time.Hour
	}
	return c.AccessTokenLifespan
}

// GetRefreshTokenLifespan sets how long a refresh token is going to be valid. Defaults to 30 days. Set to -1 for
// refresh tokens that never expire.
func (c *Config) GetRefreshTokenLifespan() time.Duration {
	if c.RefreshTokenLifespan == 0 {
		return time.Hour * 24 * 30
	}
	return c.RefreshTokenLifespan
}

// GetHashCost returns the bcrypt cost factor. Defaults to 12.
func (c *Config) GetHashCost() int {
	if c.HashCost == 0 {
		return fosite.DefaultBCryptWorkFactor
	}
	return c.HashCost
}

// GetJWKSFetcherStrategy returns the JWKSFetcherStrategy.
func (c *Config) GetJWKSFetcherStrategy() fosite.JWKSFetcherStrategy {
	if c.JWKSFetcher == nil {
		c.JWKSFetcher = fosite.NewDefaultJWKSFetcherStrategy()
	}
	return c.JWKSFetcher
}

// GetTokenEntropy returns the entropy of the "message" part of a HMAC Token. Defaults to 32.
func (c *Config) GetTokenEntropy() int {
	if c.TokenEntropy == 0 {
		return 32
	}
	return c.TokenEntropy
}

// GetRedirectSecureChecker returns the checker to check if redirect URI is secure. Defaults to fosite.IsRedirectURISecure.
func (c *Config) GetRedirectSecureChecker() func(*url.URL) bool {
	if c.RedirectSecureChecker == nil {
		return fosite.IsRedirectURISecure
	}
	return c.RedirectSecureChecker
}

// GetRefreshTokenScopes returns which scopes will provide refresh tokens.
func (c *Config) GetRefreshTokenScopes() []string {
	if c.RefreshTokenScopes == nil {
		return []string{"offline", "offline_access"}
	}
	return c.RefreshTokenScopes
}

// GetMinParameterEntropy returns MinParameterEntropy if set. Defaults to fosite.MinParameterEntropy.
func (c *Config) GetMinParameterEntropy() int {
	if c.MinParameterEntropy == 0 {
		return fosite.MinParameterEntropy
	} else {
		return c.MinParameterEntropy
	}
}

// GetJWTMaxDuration specified the maximum amount of allowed `exp` time for a JWT. It compares
// the time with the JWT's `exp` time if the JWT time is larger, will cause the JWT to be invalid.
//
// Defaults to a day.
func (c *Config) GetJWTMaxDuration() time.Duration {
	if c.GrantTypeJWTBearerMaxDuration == 0 {
		return time.Hour * 24
	}
	return c.GrantTypeJWTBearerMaxDuration
}

// GetClientAuthenticationStrategy returns the configured client authentication strategy.
// Defaults to nil.
// Note that on a nil strategy `fosite.Fosite` fallbacks to its default client authentication strategy
// `fosite.Fosite.DefaultClientAuthenticationStrategy`
func (c *Config) GetClientAuthenticationStrategy() fosite.ClientAuthenticationStrategy {
	return c.ClientAuthenticationStrategy
}
