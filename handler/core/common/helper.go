package common

import (
	"net/http"

	"time"

	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"golang.org/x/net/context"
)

func IssueAccessToken(ctx context.Context, accessTokenStrategy core.AccessTokenStrategy, accessTokenStorage core.AccessTokenStorage, accessTokenLifespan time.Duration, req *http.Request, requester AccessRequester, responder AccessResponder) error {
	token, signature, err := accessTokenStrategy.GenerateAccessToken(ctx, req, requester)
	if err != nil {
		return errors.New(ErrServerError)
	} else if err := accessTokenStorage.CreateAccessTokenSession(ctx, signature, requester); err != nil {
		return errors.New(ErrServerError)
	}

	responder.SetAccessToken(token)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(accessTokenLifespan / time.Second)
	responder.SetScopes(requester.GetGrantedScopes())
	return nil
}
