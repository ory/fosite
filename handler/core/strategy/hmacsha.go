package strategy

import (
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/enigma"
	"golang.org/x/net/context"
	"net/http"
)

type HMACSHAStrategy struct {
	Enigma *enigma.HMACSHAEnigma
}

func (h HMACSHAStrategy) GenerateAccessToken(_ context.Context, _ *http.Request, requester fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate(requester.GetClient().GetHashedSecret())
}

func (h HMACSHAStrategy) ValidateAccessToken(token string, _ context.Context, _ *http.Request, requester fosite.Requester) (signature string, err error) {
	return h.Enigma.Validate(requester.GetClient().GetHashedSecret(), token)
}

func (h HMACSHAStrategy) GenerateRefreshToken(_ context.Context, _ *http.Request, requester fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate(requester.GetClient().GetHashedSecret())
}

func (h HMACSHAStrategy) ValidateRefreshToken(token string, _ context.Context, _ *http.Request, requester fosite.Requester) (signature string, err error) {
	return h.Enigma.Validate(requester.GetClient().GetHashedSecret(), token)
}

func (h HMACSHAStrategy) GenerateAuthorizeCode(_ context.Context, _ *http.Request, requester fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate(requester.GetClient().GetHashedSecret())
}

func (h HMACSHAStrategy) ValidateAuthorizeCode(token string, _ context.Context, _ *http.Request, requester fosite.Requester) (signature string, err error) {
	return h.Enigma.Validate(requester.GetClient().GetHashedSecret(), token)
}
