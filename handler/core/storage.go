package core

import (
	"github.com/ory-am/fosite"
)

type AuthorizeSession struct {
	RequestRedirectURI string
	Extra              interface{}
}

type AuthorizeExplicitStorage interface {
	CreateAuthorizeCodeSession(string, fosite.AuthorizeRequester, *AuthorizeSession) error

	GetAuthorizeCodeSession(string, *AuthorizeSession) (fosite.AuthorizeRequester, error)

	DeleteAuthorizeCodeSession(code string) error

	TokenStorage
}

type AuthorizeImplicitStorage interface {
	CreateImplicitAccessTokenSession(string, fosite.AuthorizeRequester, *AuthorizeSession) error
}

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
