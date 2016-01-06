package fosite

import (
	"github.com/ory-am/fosite/generator"
)

type OAuth2 struct {
	AllowedResponseTypes      []string
	AllowedTokenResponseTypes []string
	Lifetime                  int32
	Store                     Storage
	Entropy                   int32
	AuthorizeCodeGenerator    generator.Generator
	ResponseTypeHandlers      []ResponseTypeHandler
}

func NewDefaultOAuth2(store Storage) *OAuth2 {
	return &OAuth2{
		AllowedResponseTypes:      []string{"code", "token", "id_token"},
		AllowedTokenResponseTypes: []string{},
		Lifetime:                  3600,
		Entropy:                   128,
		AuthorizeCodeGenerator:    &generator.CryptoGenerator{},
		Store: store,
	}
}
