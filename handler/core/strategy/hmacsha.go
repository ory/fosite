package strategy

import (
	"github.com/ory-am/fosite"
	enigma "github.com/ory-am/fosite/token/hmac"
	"golang.org/x/net/context"
)

type HMACSHAStrategy struct {
	Enigma *enigma.HMACStrategy
}

func (h HMACSHAStrategy) GenerateAccessToken(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

func (h HMACSHAStrategy) ValidateAccessToken(_ context.Context, _ fosite.Requester, token string) (signature string, err error) {
	return h.Enigma.Validate(token)
}

func (h HMACSHAStrategy) GenerateRefreshToken(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

func (h HMACSHAStrategy) ValidateRefreshToken(_ context.Context, _ fosite.Requester, token string) (signature string, err error) {
	return h.Enigma.Validate(token)
}

func (h HMACSHAStrategy) GenerateAuthorizeCode(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

func (h HMACSHAStrategy) ValidateAuthorizeCode(_ context.Context, _ fosite.Requester, token string) (signature string, err error) {
	return h.Enigma.Validate(token)
}
