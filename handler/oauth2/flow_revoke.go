package oauth2

import (
	"github.com/ory-am/fosite"
	"golang.org/x/net/context"
)

type TokenRevocationHandler struct {
	TokenRevocationStorage TokenRevocationStorage
}

// RevokeToken implements https://tools.ietf.org/html/rfc7009#section-2.1
// The token type hint indicates which token type check should be performed first.
func (r *TokenRevocationHandler) RevokeToken(ctx context.Context, token string, tokenType fosite.TokenType) error {
	revokeFuncs := []func(){
		func() {
			// Refresh token
			signature := r.TokenRevocationStorage.RefreshTokenSignature(token)
			r.TokenRevocationStorage.RevokeRefreshToken(ctx, signature)
		},
		func() {
			// Access token
			signature := r.TokenRevocationStorage.AccessTokenSignature(token)
			r.TokenRevocationStorage.RevokeAccessToken(ctx, signature)
		},
	}

	// Token type hinting
	if tokenType == fosite.AccessToken {
		revokeFuncs[0], revokeFuncs[1] = revokeFuncs[1], revokeFuncs[0]
	}

	revokeFuncs[0]()
	revokeFuncs[1]()

	return nil
}
