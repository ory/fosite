package implicit

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"golang.org/x/net/context"
)

func IssueImplicitAccessToken(accessTokenStrategy core.AccessTokenStrategy, store ImplicitGrantStorage, accessTokenLifespan time.Duration, ctx context.Context, req *http.Request, ar AuthorizeRequester, resp AuthorizeResponder) error {
	// Generate the code
	token, signature, err := accessTokenStrategy.GenerateAccessToken(ctx, req, ar)
	if err != nil {
		return errors.New(ErrServerError)
	} else if err := store.CreateImplicitAccessTokenSession(signature, ar); err != nil {
		return errors.New(ErrServerError)
	}

	resp.AddFragment("access_token", token)
	resp.AddFragment("expires_in", strconv.Itoa(int(accessTokenLifespan/time.Second)))
	resp.AddFragment("token_type", "bearer")
	resp.AddFragment("state", ar.GetState())
	resp.AddFragment("scope", strings.Join(ar.GetGrantedScopes(), "+"))
	ar.SetResponseTypeHandled("token")

	return nil
}
