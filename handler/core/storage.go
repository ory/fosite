package core

import (
	"github.com/ory-am/fosite"
	"golang.org/x/net/context"
)

type CoreStorage interface {
	AuthorizeCodeStorage
	AccessTokenStorage
	RefreshTokenStorage
}

type AuthorizeCodeStorage interface {
	CreateAuthorizeCodeSession(
		ctx context.Context,
		code string,
		request fosite.Requester,
	) (context.Context, error)

	GetAuthorizeCodeSession(
		ctx context.Context,
		code string,
		session interface{},
	) (context.Context, fosite.Requester, error)

	DeleteAuthorizeCodeSession(
		ctx context.Context,
		code string,
	) (context.Context, error)
}

type AccessTokenStorage interface {
	CreateAccessTokenSession(
		ctx context.Context,
		signature string,
		request fosite.Requester,
	) (context.Context, error)

	GetAccessTokenSession(
		ctx context.Context,
		signature string,
		session interface{},
	) (context.Context, fosite.Requester, error)

	DeleteAccessTokenSession(
		ctx context.Context,
		signature string,
	) (context.Context, error)
}

type RefreshTokenStorage interface {
	CreateRefreshTokenSession(
		ctx context.Context,
		signature string,
		request fosite.Requester,
	) (context.Context, error)

	GetRefreshTokenSession(
		ctx context.Context,
		signature string,
		session interface{},
	) (context.Context, fosite.Requester, error)

	DeleteRefreshTokenSession(
		ctx context.Context,
		signature string,
	) (context.Context, error)
}
