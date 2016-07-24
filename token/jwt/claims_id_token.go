package jwt

import "time"

type IDTokenClaims struct {
	Issuer          string
	Subject         string
	Audience        string
	Nonce           string
	ExpiresAt       time.Time
	IssuedAt        time.Time
	AuthTime        time.Time
	AccessTokenHash []byte
	CodeHash        []byte
	Extra           map[string]interface{}
}

func (c *IDTokenClaims) ToMap() map[string]interface{} {
	var ret = Copy(c.Extra)
	ret["sub"] = c.Subject
	ret["iss"] = c.Issuer
	ret["aud"] = c.Audience
	ret["nonce"] = c.Nonce

	if len(c.AccessTokenHash) > 0 {
		ret["at_hash"] = c.AccessTokenHash
	}

	if len(c.CodeHash) > 0 {
		ret["c_hash"] = c.CodeHash
	}

	if !c.AuthTime.IsZero() {
		ret["auth_time"] = c.AuthTime.Unix()
	}
	ret["iat"] = c.IssuedAt.Unix()
	ret["exp"] = c.ExpiresAt.Unix()
	return ret

}

func (c *IDTokenClaims) Add(key string, value interface{}) {
	if c.Extra == nil {
		c.Extra = make(map[string]interface{})
	}
	c.Extra[key] = value
}

func (c *IDTokenClaims) Get(key string) interface{} {
	return c.ToMap()[key]
}
