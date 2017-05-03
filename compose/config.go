package compose

import "time"

type Config struct {
	// AccessTokenLifespan sets how long an access token is going to be valid. Defaults to one hour.
	AccessTokenLifespan time.Duration

	// AuthorizeCodeLifespan sets how long an authorize code is going to be valid. Defaults to fifteen minutes.
	AuthorizeCodeLifespan time.Duration

	// IDTokenLifespan sets how long an id token is going to be valid. Defaults to one hour.
	IDTokenLifespan time.Duration

	// RefreshTokenLifespan sets how long a refresh token is going to be valid. Defaults to one week.
	RefreshTokenLifespan time.Duration

	// HashCost sets the cost of the password hashing cost. Defaults to 12.
	HashCost int
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

// GetRefreshTokenLifespan returns how long a refresh token should be valid. Defaults to one week.
func (c *Config) GetRefreshTokenLifespan() time.Duration {
	if c.RefreshTokenLifespan == 0 {
		return time.Hour * 24 * 7
	}
	return c.RefreshTokenLifespan
}

// GetHashCost returns the password hashing cost. Defaults to 12.
func (c *Config) GetHashCost() int {
	if c.HashCost == 0 {
		return 12
	}
	return c.HashCost
}
