package oauth2

import (
	"net/http"
	"time"

	"github.com/ory-am/fosite"
	"golang.org/x/net/context"
)

type HandleHelper struct {
	AccessTokenStrategy AccessTokenStrategy
	AccessTokenStorage  AccessTokenStorage
	AccessTokenLifespan time.Duration
}

func (h *HandleHelper) IssueAccessToken(ctx context.Context, req *http.Request, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	token, signature, err := h.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return err
	} else if err := h.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, requester); err != nil {
		return err
	}

	responder.SetAccessToken(token)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(h.AccessTokenLifespan / time.Second)
	responder.SetScopes(requester.GetGrantedScopes())
	return nil
}
