package fosite

import "github.com/ory-am/fosite/generator"

type Config struct {
	AllowedResponseTypes      []string
	AllowedTokenResponseTypes []string
	Lifetime                  int32
	Store                     Storage
	Entropy                   int32
	AuthorizeCodeGenerator    generator.Generator
}

func NewDefaultConfig() *Config {
	return &Config{
		AllowedResponseTypes:      []string{"code", "token", "id_token"},
		AllowedTokenResponseTypes: []string{},
		Lifetime:                  3600,
		Entropy:                   128,
		AuthorizeCodeGenerator:    &generator.CryptoGenerator{},
	}
}
