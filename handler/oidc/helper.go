package oidc

import (
	"net/http"

	. "github.com/ory-am/fosite"
	"golang.org/x/net/context"
)

type IDTokenHandleHelper struct {
	IDTokenStrategy OpenIDConnectTokenStrategy
}

func (i *IDTokenHandleHelper) generateIDToken(ctx context.Context, netr *http.Request, fosr Requester) (token string, err error) {
	token, err = i.IDTokenStrategy.GenerateIDToken(ctx, netr, fosr)
	if err != nil {
		return "", err
	}

	fosr.GrantScope("openid")
	return token, nil
}

func (i *IDTokenHandleHelper) IssueImplicitIDToken(ctx context.Context, req *http.Request, ar Requester, resp AuthorizeResponder) error {
	token, err := i.generateIDToken(ctx, req, ar)
	if err != nil {
		return err
	}

	resp.AddFragment("id_token", token)
	return nil
}

func (i *IDTokenHandleHelper) IssueExplicitIDToken(ctx context.Context, req *http.Request, ar Requester, resp AccessResponder) error {
	token, err := i.generateIDToken(ctx, req, ar)
	if err != nil {
		return err
	}

	resp.SetExtra("id_token", token)
	return nil
}
