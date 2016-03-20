package core

import (
	"github.com/ory-am/fosite"
	"golang.org/x/net/context"
	"net/http"
	"strings"
)

type CoreValidator struct {
	AccessTokenStrategy
	AccessTokenStorage
}

func (c *CoreValidator) ValidateRequest(ctx context.Context, req *http.Request, accessRequest fosite.AccessRequester) error {
	auth :=  req.Header.Get("Authorization")
	split := strings.SplitN(auth, " ", 2)
	if (len(split) != 2 || split[0] != "Bearer") {
		return fosite.ErrUnknownRequest
	}

	token := split[1]
	sig, err := c.AccessTokenStrategy.ValidateAccessToken(ctx, token, accessRequest)
	if err != nil {
		return err
	}

	if _, err := c.AccessTokenStorage.GetAccessTokenSession(ctx, sig, accessRequest.GetSession()); err != nil {
		return err
	}

	return nil
}