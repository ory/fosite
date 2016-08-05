package oauth2

import (
	"reflect"
	"time"

	"github.com/ory-am/fosite"
	enigma "github.com/ory-am/fosite/token/hmac"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

type HMACSHAStrategy struct {
	Enigma                *enigma.HMACStrategy
	AccessTokenLifespan   time.Duration
	AuthorizeCodeLifespan time.Duration
}

func (h HMACSHAStrategy) AccessTokenSignature(token string) string {
	return h.Enigma.Signature(token)
}
func (h HMACSHAStrategy) RefreshTokenSignature(token string) string {
	return h.Enigma.Signature(token)
}
func (h HMACSHAStrategy) AuthorizeCodeSignature(token string) string {
	return h.Enigma.Signature(token)
}

func (h HMACSHAStrategy) GenerateAccessToken(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

func (h HMACSHAStrategy) ValidateAccessToken(_ context.Context, r fosite.Requester, token string) (err error) {
	if session, ok := r.GetSession().(HMACSessionContainer); !ok {
		return errors.Errorf("Session must be of type HMACSessionContainer, got: %s", reflect.TypeOf(r.GetSession()))
	} else if session.AccessTokenExpiresAt(r.GetRequestedAt().Add(h.AccessTokenLifespan)).Before(time.Now()) {
		return errors.Errorf("Access token expired at %s", session.AccessTokenExpiresAt(r.GetRequestedAt().Add(h.AccessTokenLifespan)))
	}
	return h.Enigma.Validate(token)
}

func (h HMACSHAStrategy) GenerateRefreshToken(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

func (h HMACSHAStrategy) ValidateRefreshToken(_ context.Context, _ fosite.Requester, token string) (err error) {
	return h.Enigma.Validate(token)
}

func (h HMACSHAStrategy) GenerateAuthorizeCode(_ context.Context, _ fosite.Requester) (token string, signature string, err error) {
	return h.Enigma.Generate()
}

func (h HMACSHAStrategy) ValidateAuthorizeCode(_ context.Context, r fosite.Requester, token string) (err error) {
	if session, ok := r.GetSession().(HMACSessionContainer); !ok {
		return errors.Errorf("Session must be of type HMACSessionContainer, got: %s", reflect.TypeOf(r.GetSession()))
	} else if session.AuthorizeCodeExpiresAt(r.GetRequestedAt().Add(h.AuthorizeCodeLifespan)).Before(time.Now()) {
		return errors.Errorf("Authorize code expired at %s", session.AuthorizeCodeExpiresAt(r.GetRequestedAt().Add(h.AccessTokenLifespan)))
	}

	return h.Enigma.Validate(token)
}
