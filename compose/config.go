// Copyright © 2017 Aeneas Rekkas <aeneas+oss@aeneas.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compose

import (
	"time"

	"github.com/ory/fosite"
)

type Config struct {
	// AccessTokenLifespan sets how long an access token is going to be valid. Defaults to one hour.
	AccessTokenLifespan time.Duration

	// AuthorizeCodeLifespan sets how long an authorize code is going to be valid. Defaults to fifteen minutes.
	AuthorizeCodeLifespan time.Duration

	// IDTokenLifespan sets how long an id token is going to be valid. Defaults to one hour.
	IDTokenLifespan time.Duration

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
}

// GetScopeStrategy returns the scope strategy to be used. Defaults to glob scope strategy.
func (c *Config) GetScopeStrategy() fosite.ScopeStrategy {
	if c.ScopeStrategy == nil {
		c.ScopeStrategy = fosite.WildcardScopeStrategy
	}
	return c.ScopeStrategy
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

// GetAccessTokenLifespan returns how long a refresh token should be valid. Defaults to one hour.
func (c *Config) GetAccessTokenLifespan() time.Duration {
	if c.AccessTokenLifespan == 0 {
		return time.Hour
	}
	return c.AccessTokenLifespan
}

// GetAccessTokenLifespan returns how long a refresh token should be valid. Defaults to one hour.
func (c *Config) GetHashCost() int {
	if c.HashCost == 0 {
		return 12
	}
	return c.HashCost
}
