package oauth2

import (
	"github.com/ory-am/fosite"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

type JWTAccessTokenStrategy interface {
	AccessTokenStrategy
	JWTStrategy
}

type StatelessJWTValidator struct {
	JWTAccessTokenStrategy
	ScopeStrategy fosite.ScopeStrategy
}

func (v *StatelessJWTValidator) IntrospectToken(ctx context.Context, token string, tokenType fosite.TokenType, accessRequest fosite.AccessRequester, scopes []string) (err error) {
	or, err := v.JWTAccessTokenStrategy.ValidateJWT(fosite.AccessToken, token)
	if err != nil {
		return err
	}

	for _, scope := range scopes {
		if scope == "" {
			continue
		}

		if !v.ScopeStrategy(or.GetGrantedScopes(), scope) {
			return errors.WithStack(fosite.ErrInvalidScope)
		}
	}

	accessRequest.Merge(or)
	return nil
}
