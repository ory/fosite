package rfc8693

import (
	"context"
	"time"
)

const (
	// AccessTokenType is the access token type issued by the same provider
	AccessTokenType string = "urn:ietf:params:oauth:token-type:access_token"
	// RefreshTokenType is the refresh token type issued by the same provider
	RefreshTokenType string = "urn:ietf:params:oauth:token-type:refresh_token"
	// IDTokenType is the id_token type issued by the same provider
	IDTokenType string = "urn:ietf:params:oauth:token-type:id_token"
	// JWTTokenType is the JWT type that may be issued by a different provider
	JWTTokenType string = "urn:ietf:params:oauth:token-type:jwt"
)

type ConfigProvider interface {
	GetTokenTypes(ctx context.Context) map[string]TokenType

	GetDefaultRequestedTokenType(ctx context.Context) string

	GetIssuer(ctx context.Context) string

	// GetIDTokenLifespan returns the ID token lifespan.
	GetIDTokenLifespan(ctx context.Context) time.Duration
}
