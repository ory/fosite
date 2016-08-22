package jwt

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pborman/uuid"
)

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

// ToMap will transform the headers to a map structure
func (c *JWTClaims) ToMap() map[string]interface{} {
	var ret = Copy(c.Extra)

	ret["jti"] = c.JTI
	if c.JTI == "" {
		ret["jti"] = uuid.New()
	}

	ret["sub"] = c.Subject
	ret["iss"] = c.Issuer
	ret["aud"] = c.Audience
	ret["iat"] = float64(c.IssuedAt.Unix())  // jwt-go does not support int64 as datatype
	ret["nbf"] = float64(c.NotBefore.Unix()) // jwt-go does not support int64 as datatype
	ret["exp"] = float64(c.ExpiresAt.Unix()) // jwt-go does not support int64 as datatype
	return ret
}

// Add will add a key-value pair to the extra field
func (c *JWTClaims) Add(key string, value interface{}) {
	if c.Extra == nil {
		c.Extra = make(map[string]interface{})
	}
	c.Extra[key] = value
}

// Get will get a value from the extra field based on a given key
func (c JWTClaims) Get(key string) interface{} {
	return c.ToMap()[key]
}

// ToMapClaims will return a jwt-go MapClaims representaion
func (c JWTClaims) ToMapClaims() jwt.MapClaims {
	return c.ToMap()
}
