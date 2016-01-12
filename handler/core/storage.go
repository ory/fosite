package core

import (
	"github.com/ory-am/fosite"
)

type TokenSession struct {
	Extra interface{}
}

type AuthorizeSession struct {
	RequestRedirectURI string
	Extra              interface{}
}

type AuthorizeCodeStorage interface {
	CreateAuthorizeCodeSession(string, fosite.AuthorizeRequester, *AuthorizeSession) error

	GetAuthorizeCodeSession(string, *AuthorizeSession) (fosite.AuthorizeRequester, error)

	DeleteAuthorizeCodeSession(code string) error
}

type AccessTokenStorage interface {
	CreateAccessTokenSession(signature string, access fosite.AccessRequester, session *TokenSession) error

	GetAccessTokenSession(signature string, session *TokenSession) (fosite.AccessRequester, error)

	DeleteAccessTokenSession(signature string) error
}

type RefreshTokenStorage interface {
	CreateRefreshTokenSession(signature string, access fosite.AccessRequester, session *TokenSession) error

	GetRefreshTokenSession(signature string, session *TokenSession) (fosite.AccessRequester, error)

	DeleteRefreshTokenSession(signature string) error
}
