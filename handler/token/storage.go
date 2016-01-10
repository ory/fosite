package token

import (
	"github.com/ory-am/fosite"
)

type TokenSession struct {
	Extra interface{}
}

type TokenStorage interface {
	CreateAccessTokenSession(signature string, access fosite.AccessRequester, session *TokenSession) error

	GetAccessTokenSession(signature string, session *TokenSession) (fosite.AccessRequester, error)

	DeleteAccessTokenSession(signature string) error

	CreateRefreshTokenSession(signature string, access fosite.AccessRequester, session *TokenSession) error

	GetRefreshTokenSession(signature string, session *TokenSession) (fosite.AccessRequester, error)

	DeleteRefreshTokenSession(signature string) error
}
