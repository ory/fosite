package strategy

import (
	"errors"
	"net/http"

	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/enigma"
	"github.com/ory-am/fosite/enigma/jwthelper"
	"golang.org/x/net/context"
)

type JWTStrategy struct {
	Enigma *enigma.JWTEnigma
}

func (h JWTStrategy) GenerateAccessToken(_ context.Context, _ *http.Request, requester fosite.Requester) (token string, signature string, err error) {
	if jwtSession, ok := requester.GetSession().(*jwthelper.JWTSession); ok {
		return h.Enigma.Generate(jwtSession.JWTClaimsCtx, jwtSession.JWTHeaders)
	}
	return "", "", errors.New("Session must be of type JWTSession")
}

func (h JWTStrategy) ValidateAccessToken(token string, _ context.Context, _ *http.Request, requester fosite.Requester) (signature string, err error) {
	return h.Enigma.Validate(requester.GetClient().GetHashedSecret(), token)
}

func (h JWTStrategy) GenerateRefreshToken(_ context.Context, _ *http.Request, requester fosite.Requester) (token string, signature string, err error) {
	if jwtSession, ok := requester.GetSession().(*jwthelper.JWTSession); ok {
		return h.Enigma.Generate(jwtSession.JWTClaimsCtx, jwtSession.JWTHeaders)
	}
	return "", "", errors.New("Session must be of type JWTSession")
}

func (h JWTStrategy) ValidateRefreshToken(token string, _ context.Context, _ *http.Request, requester fosite.Requester) (signature string, err error) {
	return h.Enigma.Validate(requester.GetClient().GetHashedSecret(), token)
}

func (h JWTStrategy) GenerateAuthorizeCode(_ context.Context, _ *http.Request, requester fosite.Requester) (token string, signature string, err error) {
	if jwtSession, ok := requester.GetSession().(*jwthelper.JWTSession); ok {
		return h.Enigma.Generate(jwtSession.JWTClaimsCtx, jwtSession.JWTHeaders)
	}
	return "", "", errors.New("Session must be of type JWTSession")
}

func (h JWTStrategy) ValidateAuthorizeCode(token string, _ context.Context, _ *http.Request, requester fosite.Requester) (signature string, err error) {
	return h.Enigma.Validate(requester.GetClient().GetHashedSecret(), token)
}
