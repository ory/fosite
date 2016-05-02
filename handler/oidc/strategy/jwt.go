package strategy

import (
	"errors"
	"net/http"

	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/token/jwt"
	"golang.org/x/net/context"
)

type IDTokenContainer interface {
	// GetJWTClaims returns the claims
	GetIDTokenClaims() jwt.Mapper

	// GetJWTHeaderContext returns the header
	GetIDTokenHeader() jwt.Mapper
}

// IDTokenSession is a session container for the id token
type IDTokenSession struct {
	Claims  *jwt.IDTokenClaims
	Headers *jwt.Header
}

func (t *IDTokenSession) GetIDTokenHeader() jwt.Mapper {
	return t.Headers
}

func (t *IDTokenSession) GetIDTokenClaims() jwt.Mapper {
	return t.Claims
}

type JWTStrategy struct {
	Enigma *jwt.Enigma
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

		if requester.GetRequestForm().Get("max_age") != "" && idcs.Get("auth_time") == nil {
			return "", errors.New("auth_time is required when max_age is set")
		}

		token, _, err := h.Enigma.Generate(idcs, jwtSession.GetIDTokenHeader())
		return token, err
	}
	return "", errors.New("Session must be of type IDTokenContainer")
}
