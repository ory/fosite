package core

import (
	"github.com/ory-am/fosite"
	"golang.org/x/net/context"
	"net/http"
)

type CoreValidator struct {
	AccessTokenStrategy
	AccessTokenStorage
}

func (c *CoreValidator) ValidateRequest(ctx context.Context, req *http.Request, accessRequest fosite.AccessRequester) error {
	return fosite.ErrUnknownRequest
}