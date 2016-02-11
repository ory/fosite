package jwt

import (
	"encoding/json"
	"github.com/pborman/uuid"
	"time"
)

// Claims represent a token's claims.
type Claims struct {
	Subject        string
	IssuedAt       time.Time
	Issuer         string
	NotValidBefore time.Time
	Audience       string
	ExpiresAt      time.Time
	ID             string
	Extra          map[string]interface{}
}

func (c *Claims) ToMap() map[string]interface{} {
	ret := map[string]interface{}{}
	for k, v := range c.Extra {
		ret[k] = v
	}
	ret["sub"] = c.Subject
	ret["iat"] = c.IssuedAt.Unix()
	ret["iss"] = c.Issuer
	ret["nbf"] = c.NotValidBefore.Unix()
	ret["aud"] = c.Audience
	ret["exp"] = c.ExpiresAt.Unix()
	ret["jti"] = uuid.New()
	if c.ID != "" {
		ret["jti"] = c.ID
	}
	return ret
}

func ClaimsFromMap(m map[string]interface{}) *Claims {
	var filter = map[string]bool{"sub": true, "iat": true, "iss": true, "nbf": true, "aud": true, "exp": true, "jti": true}
	var extra = map[string]interface{}{}

	// filter known values from extra.
	for k, v := range m {
		if _, ok := filter[k]; !ok {
			extra[k] = v
		}
	}

	return &Claims{
		Subject:   toString(m["sub"]),
		IssuedAt:  toTime(m["iat"]),
		Issuer:    toString(m["iss"]),
		NotValidBefore: toTime(m["nbf"]),
		Audience:  toString(m["aud"]),
		ExpiresAt: toTime(m["exp"]),
		ID:        toString(m["jti"]),
		Extra:     extra,
	}
}

// AssertExpired checks if JWT is expired.
func (c *Claims) AssertExpired() bool {
	return c.ExpiresAt.Before(time.Now())
}

// AssertNotYetValid maskes sure that the JWT is not used before valid date.
func (c *Claims) AssertNotYetValid() bool {
	return c.NotValidBefore.After(time.Now())
}

// String marshals the claims and returns them as a string representation.
func (c Claims) String() (string, error) {
	result, err := json.Marshal(c.ToMap())
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func toString(i interface{}) string {
	if i == nil {
		return ""
	}

	if s, ok := i.(string); ok {
		return s
	}

	return ""
}

func toTime(i interface{}) time.Time {
	if i == nil {
		return time.Time{}
	}

	if t, ok := i.(int64); ok {
		return time.Unix(t, 0)
	}

	return time.Time{}
}