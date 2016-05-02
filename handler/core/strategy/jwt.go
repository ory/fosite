package strategy

import (
	"errors"

	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/token/jwt"
	"golang.org/x/net/context"
)

type JWTSessionContainer interface {
	// GetJWTClaims returns the claims.
	GetJWTClaims() *jwt.JWTClaims

	// GetJWTHeader returns the header.
	GetJWTHeader() *jwt.Header
}

// JWTSession Container for the JWT session.
type JWTSession struct {
	JWTClaims *jwt.JWTClaims
	JWTHeader *jwt.Header
}

func (j *JWTSession) GetJWTClaims() *jwt.JWTClaims {
	return j.JWTClaims
}

func (j *JWTSession) GetJWTHeader() *jwt.Header {
	return j.JWTHeader
}

// RS256JWTStrategy is a JWT RS256 strategy.
type RS256JWTStrategy struct {
	*jwt.RS256JWTStrategy
}

func (h *RS256JWTStrategy) GenerateAccessToken(_ context.Context, requester fosite.Requester) (token string, signature string, err error) {
	return h.generate(requester)
}

func (h *RS256JWTStrategy) ValidateAccessToken(_ context.Context, _ fosite.Requester, token string) (signature string, err error) {
	return h.validate(token)
}

func (h *RS256JWTStrategy) GenerateRefreshToken(_ context.Context, requester fosite.Requester) (token string, signature string, err error) {
	return h.generate(requester)
}

func (h *RS256JWTStrategy) ValidateRefreshToken(_ context.Context, _ fosite.Requester, token string) (signature string, err error) {
	return h.validate(token)
}

func (h *RS256JWTStrategy) GenerateAuthorizeCode(_ context.Context, requester fosite.Requester) (token string, signature string, err error) {
	return h.generate(requester)
}

func (h *RS256JWTStrategy) ValidateAuthorizeCode(_ context.Context, requester fosite.Requester, token string) (signature string, err error) {
	return h.validate(token)
}

func (h *RS256JWTStrategy) validate(token string) (string, error) {
	t, err := h.RS256JWTStrategy.Decode(token)
	if err != nil {
		return "", err
	}

	claims := jwt.JWTClaimsFromMap(t.Claims)
	if claims.IsNotYetValid() || claims.IsExpired() {
		return "", errors.New("Token claims did not validate")
	}

	return h.RS256JWTStrategy.GetSignature(token)
}

func (h *RS256JWTStrategy) generate(requester fosite.Requester) (string, string, error) {
	if jwtSession, ok := requester.GetSession().(JWTSessionContainer); ok {
		if jwtSession.GetJWTClaims() != nil {
			return h.RS256JWTStrategy.Generate(jwtSession.GetJWTClaims(), jwtSession.GetJWTHeader())
		}
		return "", "", errors.New("GetTokenClaims() must not be nil")
	}
	return "", "", errors.New("Session must be of type JWTSession")

}
