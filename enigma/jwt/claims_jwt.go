package jwt

import (
	"time"
	"github.com/pborman/uuid"
	"encoding/json"
)

// JWTClaims represent a token's claims.
type JWTClaims struct {
	Subject        string
	IssuedAt       time.Time
	Issuer         string
	NotValidBefore time.Time
	Audience       string
	ExpiresAt      time.Time
	ID             string
	Extra          map[string]interface{}
}

func (c *JWTClaims) ToMap() map[string]interface{} {
	ret := map[string]interface{}{}
	for k, v := range c.Extra {
		ret[k] = v
	}
	ret["sub"] = c.Subject
	ret["iss"] = c.Issuer
	ret["aud"] = c.Audience
	ret["iat"] = c.IssuedAt.Unix()
	ret["nbf"] = c.NotValidBefore.Unix()
	ret["exp"] = c.ExpiresAt.Unix()
	ret["jti"] = uuid.New()
	if c.ID != "" {
		ret["jti"] = c.ID
	}
	return ret
}

func (c *JWTClaims) Add(key string, value interface{}) {
	if c.Extra == nil {
		c.Extra = make(map[string]interface{})
	}
	c.Extra[key] = value
}

func JWTClaimsFromMap(m map[string]interface{}) *JWTClaims {
	var filter = map[string]bool{"sub": true, "iat": true, "iss": true, "nbf": true, "aud": true, "exp": true, "jti": true}
	var extra = map[string]interface{}{}

	// filter known values from extra.
	for k, v := range m {
		if _, ok := filter[k]; !ok {
			extra[k] = v
		}
	}

	return &JWTClaims{
		Subject:        toString(m["sub"]),
		IssuedAt:       toTime(m["iat"]),
		Issuer:         toString(m["iss"]),
		NotValidBefore: toTime(m["nbf"]),
		Audience:       toString(m["aud"]),
		ExpiresAt:      toTime(m["exp"]),
		ID:             toString(m["jti"]),
		Extra:          extra,
	}
}

// IsExpired checks if JWT is expired.
func (c *JWTClaims) IsExpired() bool {
	return c.ExpiresAt.Before(time.Now())
}

// IsNotYetValid maskes sure that the JWT is not used before valid date.
func (c *JWTClaims) IsNotYetValid() bool {
	return c.NotValidBefore.After(time.Now())
}

// String marshals the claims and returns them as a string representation.
func (c JWTClaims) String() (string, error) {
	result, err := json.Marshal(c.ToMap())
	if err != nil {
		return "", err
	}
	return string(result), nil
}