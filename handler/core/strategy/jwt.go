package strategy

import (
	"errors"
	"net/http"

	"github.com/ory-am/fosite"
	enigma "github.com/ory-am/fosite/enigma/jwt"
	"golang.org/x/net/context"
)

type JWTSessionContainer interface {
	// GetTokenClaims returns the claims
	GetTokenClaims() *enigma.Claims

	// GetTokenHeader returns the header
	GetTokenHeader() *enigma.Header
}

// JWTSession : Container for the JWT session
type JWTSession struct {
	TokenClaims *enigma.Claims
	TokenHeader *enigma.Header
}

func (j *JWTSession) GetTokenClaims() *enigma.Claims {
	return j.TokenClaims
}

func (j *JWTSession) GetTokenHeader() *enigma.Header {
	return j.TokenHeader
}

// JWTStrategy : Strategy container
type JWTStrategy struct {
	Enigma *enigma.Enigma
}

func (h JWTStrategy) GenerateAccessToken(_ context.Context, _ *http.Request, requester fosite.Requester) (token string, signature string, err error) {
	if jwtSession, ok := requester.GetSession().(JWTSessionContainer); ok {
		if jwtSession.GetTokenClaims() != nil {
			return h.Enigma.Generate(jwtSession.GetTokenClaims(), jwtSession.GetTokenHeader())
		}
		return "", "", errors.New("GetTokenClaims() must not be nil")
	}
	return "", "", errors.New("Session must be of type JWTSession")
}

func (h JWTStrategy) ValidateAccessToken(token string, _ context.Context, _ *http.Request, requester fosite.Requester) (signature string, err error) {
	return h.Enigma.Validate(token)
}

func (h JWTStrategy) GenerateRefreshToken(_ context.Context, _ *http.Request, requester fosite.Requester) (token string, signature string, err error) {
	if jwtSession, ok := requester.GetSession().(JWTSessionContainer); ok {
		if jwtSession.GetTokenClaims() != nil {
			return h.Enigma.Generate(jwtSession.GetTokenClaims(), jwtSession.GetTokenHeader())
		}
		return "", "", errors.New("GetTokenClaims() must not be nil")
	}
	return "", "", errors.New("Session must be of type JWTSession")
}

func (h JWTStrategy) ValidateRefreshToken(token string, _ context.Context, _ *http.Request, requester fosite.Requester) (signature string, err error) {
	return h.Enigma.Validate(token)
}

func (h JWTStrategy) GenerateAuthorizeCode(_ context.Context, _ *http.Request, requester fosite.Requester) (token string, signature string, err error) {
	if jwtSession, ok := requester.GetSession().(JWTSessionContainer); ok {
		if jwtSession.GetTokenClaims() != nil {
			return h.Enigma.Generate(jwtSession.GetTokenClaims(), jwtSession.GetTokenHeader())
		}
		return "", "", errors.New("GetTokenClaims() must not be nil")
	}
	return "", "", errors.New("Session must be of type JWTSession")
}

func (h JWTStrategy) ValidateAuthorizeCode(token string, _ context.Context, _ *http.Request, requester fosite.Requester) (signature string, err error) {
	return h.Enigma.Validate(token)
}
