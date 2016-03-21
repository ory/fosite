package core

import (
	"net/http"
	"strings"

	"github.com/go-errors/errors"
	"github.com/ory-am/fosite"
	"golang.org/x/net/context"
)

type CoreValidator struct {
	AccessTokenStrategy
	AccessTokenStorage
}

func (c *CoreValidator) ValidateRequest(ctx context.Context, req *http.Request, accessRequest fosite.AccessRequester) error {
	auth := req.Header.Get("Authorization")
	split := strings.SplitN(auth, " ", 2)
	if len(split) != 2 || !strings.EqualFold(split[0], "bearer") {
		return errors.New(fosite.ErrUnknownRequest)
	}

	token := split[1]
	sig, err := c.AccessTokenStrategy.ValidateAccessToken(ctx, token, req, accessRequest)
	if err != nil {
		return errors.New(fosite.ErrRequestUnauthorized)
	}

	origreq, err := c.AccessTokenStorage.GetAccessTokenSession(ctx, sig, accessRequest.GetSession())
	if err != nil {
		return errors.New(fosite.ErrRequestUnauthorized)
	}

	accessRequest.Merge(origreq)
	return nil
}
