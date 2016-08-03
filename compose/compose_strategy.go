package compose

import (
	"crypto/rsa"

	"github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/handler/core/strategy"
	"github.com/ory-am/fosite/handler/oidc"
	oidcstrategy "github.com/ory-am/fosite/handler/oidc/strategy"
	"github.com/ory-am/fosite/token/hmac"
	"github.com/ory-am/fosite/token/jwt"
)

type CommonStrategy struct {
	core.CoreStrategy
	oidc.OpenIDConnectTokenStrategy
}

func NewOAuth2HMACStrategy(config *Config, secret []byte) *strategy.HMACSHAStrategy {
	return &strategy.HMACSHAStrategy{
		Enigma: &hmac.HMACStrategy{
			GlobalSecret: secret,
		},
		AccessTokenLifespan:   config.GetAccessTokenLifespan(),
		AuthorizeCodeLifespan: config.GetAuthorizeCodeLifespan(),
	}
}

func NewOAuth2JWTStrategy(key *rsa.PrivateKey) *strategy.RS256JWTStrategy {
	return &strategy.RS256JWTStrategy{
		RS256JWTStrategy: &jwt.RS256JWTStrategy{
			PrivateKey: key,
		},
	}
}

func NewOpenIDConnectStrategy(key *rsa.PrivateKey) *oidcstrategy.DefaultStrategy {
	return &oidcstrategy.DefaultStrategy{
		RS256JWTStrategy: &jwt.RS256JWTStrategy{
			PrivateKey: key,
		},
	}
}
