package core

import (
	"github.com/ory-am/fosite"
)

type AuthorizeCodeStorage interface {
	CreateAuthorizeCodeSession(code string, request fosite.AuthorizeRequester) (err error)

	GetAuthorizeCodeSession(code string) (request fosite.AuthorizeRequester, err error)

	DeleteAuthorizeCodeSession(code string) (err error)
}

type AccessTokenStorage interface {
	CreateAccessTokenSession(signature string, request fosite.AccessRequester) (err error)

	GetAccessTokenSession(signature string) (request fosite.AccessRequester, err error)

	DeleteAccessTokenSession(signature string) (err error)
}

type RefreshTokenStorage interface {
	CreateRefreshTokenSession(signature string, request fosite.AccessRequester) (err error)

	GetRefreshTokenSession(signature string) (request fosite.AccessRequester, err error)

	DeleteRefreshTokenSession(signature string) (err error)
}
