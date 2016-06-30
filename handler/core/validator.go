package core

import (
	"net/http"
	"strings"

	"github.com/ory-am/fosite"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

type CoreValidator struct {
	AccessTokenStrategy
	AccessTokenStorage
}

func (c *CoreValidator) ValidateRequest(ctx context.Context, req *http.Request, accessRequest fosite.AccessRequester) (context.Context, error) {
	auth := req.Header.Get("Authorization")
	split := strings.SplitN(auth, " ", 2)
	if len(split) != 2 || !strings.EqualFold(split[0], "bearer") {
		return ctx, errors.Wrap(fosite.ErrUnknownRequest, "")
	}

	return c.ValidateToken(ctx, accessRequest, split[1])
}

func (c *CoreValidator) ValidateToken(ctx context.Context, accessRequest fosite.AccessRequester, token string) (context.Context, error) {
	sig := c.AccessTokenStrategy.AccessTokenSignature(token)
	ctx, or, err := c.AccessTokenStorage.GetAccessTokenSession(ctx, sig, accessRequest.GetSession())
	if err != nil {
		return ctx, errors.Wrap(fosite.ErrRequestUnauthorized, err.Error())
	}

	if err := c.AccessTokenStrategy.ValidateAccessToken(ctx, or, token); err != nil {
		return ctx, errors.Wrap(fosite.ErrRequestUnauthorized, err.Error())
	}

	accessRequest.Merge(or)
	return ctx, nil
}
