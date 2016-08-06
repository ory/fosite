package compose

import (
	"crypto/rsa"

	"github.com/Sirupsen/logrus"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/hash"
)

type handler func(config *Config, storage interface{}, strategy interface{}) interface{}

// Compose takes a config, a storage, a strategy and handlers to instantiate an OAuth2Provider:
//
//  import "github.com/ory-am/fosite/compose"
//
//  // var storage = new(MyFositeStorage)
//  var config = Config {
//  	AccessTokenLifespan: time.Minute * 30,
// 	// check Config for further configuration options
//  }
//
//  var strategy = NewOAuth2HMACStrategy(config)
//
//  var oauth2Provider = Compose(
//  	config,
// 	storage,
// 	strategy,
//	NewOAuth2AuthorizeExplicitHandler,
//	OAuth2ClientCredentialsGrantFactory,
// 	// for a complete list refer to the docs of this package
//  )
func Compose(config *Config, storage interface{}, strategy interface{}, handlers ...handler) fosite.OAuth2Provider {
	f := &fosite.Fosite{
		Store: storage.(fosite.Storage),
		AuthorizeEndpointHandlers: fosite.AuthorizeEndpointHandlers{},
		TokenEndpointHandlers:     fosite.TokenEndpointHandlers{},
		TokenValidators:           fosite.TokenValidators{},
		Hasher:                    &hash.BCrypt{WorkFactor: config.GetHashCost()},
		Logger:                    &logrus.Logger{},
		ScopeStrategy:             fosite.HierarchicScopeStrategy,
	}

	for _, h := range handlers {
		res := h(config, storage, strategy)
		if ah, ok := res.(fosite.AuthorizeEndpointHandler); ok {
			f.AuthorizeEndpointHandlers.Append(ah)
		}
		if th, ok := res.(fosite.TokenEndpointHandler); ok {
			f.TokenEndpointHandlers.Append(th)
		}
		if tv, ok := res.(fosite.TokenValidator); ok {
			f.TokenValidators.Append(tv)
		}
	}

	return f
}

// ComposeAllEnabled returns a fosite instance with all OAuth2 and OpenID Connect handlers enabled.
func ComposeAllEnabled(config *Config, storage interface{}, secret []byte, key *rsa.PrivateKey) fosite.OAuth2Provider {
	return Compose(
		config,
		storage,
		&CommonStrategy{
			CoreStrategy:               NewOAuth2HMACStrategy(config, secret),
			OpenIDConnectTokenStrategy: NewOpenIDConnectStrategy(key),
		},
		OAuth2AuthorizeExplicitFactory,
		OAuth2AuthorizeImplicitFactory,
		OAuth2ClientCredentialsGrantFactory,
		OAuth2RefreshTokenGrantFactory,
		OAuth2ResourceOwnerPasswordCredentialsFactory,

		OpenIDConnectExplicit,
		OpenIDConnectImplicit,
		OpenIDConnectHybrid,
	)
}
