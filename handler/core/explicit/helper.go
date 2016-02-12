package explicit

import (
	"net/http"
	"strings"

	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"golang.org/x/net/context"
)

func IssueAuthorizeCode(authorizeCodeStrategy core.AuthorizeCodeStrategy, store AuthorizeCodeGrantStorage, ctx context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) error {
	code, signature, err := authorizeCodeStrategy.GenerateAuthorizeCode(ctx, req, ar)
	if err != nil {
		return errors.New(ErrServerError)
	}

	if err := store.CreateAuthorizeCodeSession(ctx, signature, ar); err != nil {
		return errors.New(ErrServerError)
	}

	resp.AddQuery("code", code)
	resp.AddQuery("state", ar.GetState())
	resp.AddQuery("scope", strings.Join(ar.GetGrantedScopes(), " "))
	ar.SetResponseTypeHandled("code")
	return nil
}
