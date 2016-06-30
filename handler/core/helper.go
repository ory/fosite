package core

import (
	"net/http"
	"time"

	. "github.com/ory-am/fosite"
	"golang.org/x/net/context"
)

type HandleHelper struct {
	AccessTokenStrategy AccessTokenStrategy
	AccessTokenStorage  AccessTokenStorage
	AccessTokenLifespan time.Duration
}

func (h *HandleHelper) IssueAccessToken(ctx context.Context, req *http.Request, requester AccessRequester, responder AccessResponder) (context.Context, error) {
	token, signature, err := h.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return ctx, err
	}

	ctx, err = h.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, requester)
	if err != nil {
		return ctx, err
	}

	responder.SetAccessToken(token)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(h.AccessTokenLifespan / time.Second)
	responder.SetScopes(requester.GetGrantedScopes())
	return ctx, nil
}
