package common

import (
	"net/http"

	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	. "github.com/ory-am/fosite/handler/oidc"
	"github.com/ory-am/fosite/handler/oidc/strategy"
	"golang.org/x/net/context"
)

func generateIDToken(ctx context.Context, idTokenStrategy OpenIDConnectTokenStrategy, req *http.Request, ar Requester) (token string, err error) {
	// OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
	// Altough optional, this is considered good practice and therefore enforced.
	if ar.GetRequestForm().Get("nonce") == "" {
		return "", errors.New(ErrInvalidRequest)
	}

	session, ok := ar.GetSession().(*strategy.IDTokenSession)
	if !ok {
		return "", errors.New(ErrServerError)
	}

	session.JWTClaims.AddExtra("nonce", ar.GetRequestForm().Get("nonce"))
	token, err = idTokenStrategy.GenerateIDToken(ctx, req, session)
	if err != nil {
		return "", errors.New(ErrServerError)
	}

	return token, nil
}

func IssueImplicitIDToken(ctx context.Context, idTokenStrategy OpenIDConnectTokenStrategy, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) error {
	token, err := generateIDToken(ctx, idTokenStrategy, req, ar)
	if err != nil {
		return err
	}

	resp.AddFragment("id_token", token)
	resp.AddFragment("state", ar.GetState())
	return nil
}

func IssueExplicitIDToken(ctx context.Context, idTokenStrategy OpenIDConnectTokenStrategy, req *http.Request, ar AccessRequester, resp AccessResponder) error {
	token, err := generateIDToken(ctx, idTokenStrategy, req, ar)
	if err != nil {
		return err
	}

	resp.SetExtra("id_token", token)
	return nil
}
