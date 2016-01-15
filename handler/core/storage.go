package core

import (
	"github.com/ory-am/fosite"
)

type AuthorizeCodeStorage interface {
	CreateAuthorizeCodeSession(code string, request fosite.Requester) (err error)

	GetAuthorizeCodeSession(code string, session interface{}) (request fosite.Requester, err error)

	DeleteAuthorizeCodeSession(code string) (err error)
}

type AccessTokenStorage interface {
	CreateAccessTokenSession(signature string, request fosite.Requester) (err error)

	GetAccessTokenSession(signature string, session interface{}) (request fosite.Requester, err error)

	DeleteAccessTokenSession(signature string) (err error)
}

type RefreshTokenStorage interface {
	CreateRefreshTokenSession(signature string, request fosite.Requester) (err error)

	GetRefreshTokenSession(signature string, session interface{}) (request fosite.Requester, err error)

	DeleteRefreshTokenSession(signature string) (err error)
}
