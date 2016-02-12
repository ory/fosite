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
	GetIDTokenClaims() *enigma.Claims
	// GetJWTHeaderContext returns the header
	GetIDTokenHeader() *enigma.Header
}

// IDTokenSession is a session container for the id token
type IDTokenSession struct {
	JWTClaims *enigma.Claims
	JWTHeader *enigma.Header
}

// JWTStrategy : Strategy container
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
