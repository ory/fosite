package jwt

import (
	"time"

	"github.com/pborman/uuid"
)

func JWTClaimsFromMap(m map[string]interface{}) *JWTClaims {
	return &JWTClaims{
		Subject:   ToString(m["sub"]),
		IssuedAt:  ToTime(m["iat"]),
		Issuer:    ToString(m["iss"]),
		NotBefore: ToTime(m["nbf"]),
		Audience:  ToString(m["aud"]),
		ExpiresAt: ToTime(m["exp"]),
		JTI:       ToString(m["jti"]),
		Extra:     Filter(m, "sub", "iss", "iat", "nbf", "aud", "exp", "jti"),
	}
}

// JWTClaims represent a token's claims.
type JWTClaims struct {
	Subject   string
	Issuer    string
	Audience  string
	JTI       string
	IssuedAt  time.Time
	NotBefore time.Time
	ExpiresAt time.Time
	Extra     map[string]interface{}
}

func (c *JWTClaims) ToMap() map[string]interface{} {
	var ret = Copy(c.Extra)

	ret["jti"] = c.JTI
	if c.JTI == "" {
		ret["jti"] = uuid.New()
	}

	ret["sub"] = c.Subject
	ret["iss"] = c.Issuer
	ret["aud"] = c.Audience
	ret["iat"] = c.IssuedAt.Unix()
	ret["nbf"] = c.NotBefore.Unix()
	ret["exp"] = c.ExpiresAt.Unix()
	return ret
}

func (c JWTClaims) Get(key string) interface{} {
	return c.ToMap()[key]
}

func (c *JWTClaims) Add(key string, value interface{}) {
	if c.Extra == nil {
		c.Extra = make(map[string]interface{})
	}
	c.Extra[key] = value
}

// IsExpired checks if JWT is expired.
func (c *JWTClaims) IsExpired() bool {
	return c.ExpiresAt.Before(time.Now())
}

// IsNotYetValid maskes sure that the JWT is not used before valid date.
func (c *JWTClaims) IsNotYetValid() bool {
	return c.NotBefore.After(time.Now())
}
