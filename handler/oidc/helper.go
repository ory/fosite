package oidc

import (
	"net/http"

	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/oidc/strategy"
	"golang.org/x/net/context"
)

type IDTokenHandleHelper struct {
	IDTokenStrategy OpenIDConnectTokenStrategy
}

func (i *IDTokenHandleHelper) generateIDToken(ctx context.Context, netr *http.Request, fosr Requester) (token string, err error) {
	nonce := fosr.GetRequestForm().Get("nonce")

	// OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
	// Altough optional, this is considered good practice and therefore enforced.
	if len(nonce) < MinParameterEntropy {
		return "", errors.New(ErrInsufficientEntropy)
	}

	session, ok := fosr.GetSession().(strategy.IDTokenContainer)
	if !ok {
		return "", errors.New(ErrMisconfiguration)
	}

	token, err = i.IDTokenStrategy.GenerateIDToken(ctx, netr, fosr)
	if err != nil {
		return "", errors.New(ErrServerError)
	}

	session.GetIDTokenClaims().Add("nonce", nonce)
	fosr.GrantScope("openid")
	return token, nil
}

func (i *IDTokenHandleHelper) IssueImplicitIDToken(ctx context.Context, req *http.Request, ar Requester, resp AuthorizeResponder) error {
	token, err := i.generateIDToken(ctx, req, ar)
	if err != nil {
		return errors.New(err)
	}

	resp.AddFragment("id_token", token)
	return nil
}

func (i *IDTokenHandleHelper) IssueExplicitIDToken(ctx context.Context, req *http.Request, ar Requester, resp AccessResponder) error {
	token, err := i.generateIDToken(ctx, req, ar)
	if err != nil {
		return errors.New(err)
	}

	resp.SetExtra("id_token", token)
	return nil
}
