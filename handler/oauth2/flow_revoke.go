package oauth2

import (
	"golang.org/x/net/context"

	"github.com/ory-am/fosite"
)

type TokenRevocationHandler struct {
	TokenRevocationStorage TokenRevocationStorage
}

// RevokeToken implements https://tools.ietf.org/html/rfc7009#section-2.1
func (r *TokenRevocationHandler) RevokeToken(ctx context.Context, token string, tokenType fosite.TokenType) error {
	if tokenType == fosite.RefreshToken {
		signature := r.TokenRevocationStorage.RefreshTokenSignature(token)
		r.TokenRevocationStorage.DeleteRefreshTokenSession(ctx, signature)
	}

	if tokenType == fosite.AccessToken {
		signature := r.TokenRevocationStorage.AccessTokenSignature(token)
		r.TokenRevocationStorage.DeleteAccessTokenSession(ctx, signature)
	}

	return nil
}
