package strategy

import (
	"errors"
	"net/http"

	"time"

	"github.com/ory-am/fosite"
	enigma "github.com/ory-am/fosite/enigma/jwt"
	"golang.org/x/net/context"
)

type IDTokenContainer interface {
	// GetJWTClaims returns the claims
	GetIDTokenClaims() enigma.Mapper

	// GetJWTHeaderContext returns the header
	GetIDTokenHeader() enigma.Mapper
}

// IDTokenSession is a session container for the id token
type IDTokenSession struct {
	*IDTokenClaims
	Header *enigma.Header
}

func IDClaimsFromMap(m map[string]interface{}) *IDTokenClaims {
	return &IDTokenClaims{
		Subject:   enigma.ToString(m["sub"]),
		IssuedAt:  enigma.ToTime(m["iat"]),
		Issuer:    enigma.ToString(m["iss"]),
		Audience:  enigma.ToString(m["aud"]),
		ExpiresAt: enigma.ToTime(m["exp"]),
		Extra:     enigma.Filter(m, "sub", "iss", "iat", "aud", "exp"),
	}
}

type IDTokenClaims struct {
	Issuer          string
	Subject         string
	Audience        string
	Nonce           string
	ExpiresAt       time.Time
	IssuedAt        time.Time
	AuthTime        time.Time
	AccessTokenHash string
	CodeHash        string
	Extra           map[string]interface{}
}

func (c *IDTokenClaims) ToMap() map[string]interface{} {
	var ret = enigma.Copy(c.Extra)
	ret["sub"] = c.Subject
	ret["iss"] = c.Issuer
	ret["aud"] = c.Audience
	ret["nonce"] = c.Nonce
	ret["auth_time"] = c.AuthTime
	ret["at_hash"] = c.AccessTokenHash
	ret["c_hash"] = c.CodeHash
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

func (t *IDTokenSession) GetIDTokenHeader() enigma.Mapper {
	return t.Header
}

func (t *IDTokenSession) GetIDTokenClaims() enigma.Mapper {
	return t.IDTokenClaims
}

type JWTStrategy struct {
	Enigma *enigma.Enigma
}

func (h JWTStrategy) GenerateIDToken(_ context.Context, _ *http.Request, requester fosite.Requester, claims map[string]interface{}) (token string, err error) {
	if jwtSession, ok := requester.GetSession().(IDTokenContainer); ok {
		idcs := jwtSession.GetIDTokenClaims()
		if idcs == nil {
			return "", errors.New("GetIDTokenClaims must not be nil")
		}

		for k, v := range claims {
			idcs.Add(k,v)
		}

		token, _, err := h.Enigma.Generate(idcs, jwtSession.GetIDTokenHeader())
		return token, err
	}
	return "", errors.New("Session must be of type IDTokenContainer")
}
