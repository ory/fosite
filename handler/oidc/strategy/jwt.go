package strategy

import (
	"errors"
	"net/http"

	"github.com/ory-am/fosite"
	enigma "github.com/ory-am/fosite/enigma/jwt"
	"golang.org/x/net/context"
)

type IDTokenContainer interface {
	// GetJWTClaims returns the claims
	GetIDTokenClaims() enigma.Mapper

	// GetJWTHeaderContext returns the header
	GetIDTokenHeader()  enigma.Mapper
}

// IDTokenSession is a session container for the id token
type IDTokenSession struct {
	IDClaims *enigma.JWTClaims
	IDToken  *enigma.Header
}

func (t *IDTokenSession) GetIDTokenHeader()  enigma.Mapper {
	return t.IDToken
}

func (t *IDTokenSession) GetIDTokenClaims()  enigma.Mapper {
	return t.IDClaims
}

type JWTStrategy struct {
	Enigma *enigma.Enigma
}

func (h JWTStrategy) GenerateIDToken(_ context.Context, _ *http.Request, requester fosite.Requester) (token string, err error) {
	if jwtSession, ok := requester.GetSession().(IDTokenContainer); ok {
		if jwtSession.GetIDTokenClaims() != nil {
			token, _, err := h.Enigma.Generate(jwtSession.GetIDTokenClaims(), jwtSession.GetIDTokenHeader())
			return token, err
		}
		return "", errors.New("GetIDTokenClaims must not be nil")
	}
	return "", errors.New("Session must be of type IDTokenContainer")
}
