package oauth2

import (
	"github.com/ory-am/fosite/token/jwt"
)

type JWTSessionContainer interface {
	// GetJWTClaims returns the claims.
	GetJWTClaims() *jwt.JWTClaims

	// GetJWTHeader returns the header.
	GetJWTHeader() *jwt.Headers
}

// JWTSession Container for the JWT session.
type JWTSession struct {
	JWTClaims *jwt.JWTClaims
	JWTHeader *jwt.Headers
}

func (j *JWTSession) GetJWTClaims() *jwt.JWTClaims {
	if j.JWTClaims == nil {
		j.JWTClaims = &jwt.JWTClaims{}
	}
	return j.JWTClaims
}

func (j *JWTSession) GetJWTHeader() *jwt.Headers {
	if j.JWTHeader == nil {
		j.JWTHeader = &jwt.Headers{}
	}
	return j.JWTHeader
}
