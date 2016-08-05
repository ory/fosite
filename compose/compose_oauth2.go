package compose

import (
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/handler/core/client"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/ory-am/fosite/handler/core/implicit"
	"github.com/ory-am/fosite/handler/core/owner"
	"github.com/ory-am/fosite/handler/core/refresh"
)

// OAuth2AuthorizeExplicitFactory creates an OAuth2 authorize code grant ("authorize explicit flow") handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2AuthorizeExplicitFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*explicit.AuthorizeExplicitGrantHandler
		*core.CoreValidator
	}{
		AuthorizeExplicitGrantHandler: &explicit.AuthorizeExplicitGrantHandler{
			AccessTokenStrategy:       strategy.(core.AccessTokenStrategy),
			RefreshTokenStrategy:      strategy.(core.RefreshTokenStrategy),
			AuthorizeCodeStrategy:     strategy.(core.AuthorizeCodeStrategy),
			AuthorizeCodeGrantStorage: storage.(explicit.AuthorizeCodeGrantStorage),
			AuthCodeLifespan:          config.GetAuthorizeCodeLifespan(),
			AccessTokenLifespan:       config.GetAccessTokenLifespan(),
			ScopeStrategy:             fosite.HierarchicScopeStrategy,
		},
		CoreValidator: &core.CoreValidator{
			CoreStrategy: strategy.(core.CoreStrategy),
			CoreStorage:  storage.(core.CoreStorage),
		},
	}
}

// OAuth2ClientCredentialsGrantFactory creates an OAuth2 client credentials grant handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2ClientCredentialsGrantFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*client.ClientCredentialsGrantHandler
		*core.CoreValidator
	}{
		ClientCredentialsGrantHandler: &client.ClientCredentialsGrantHandler{
			HandleHelper: &core.HandleHelper{
				AccessTokenStrategy: strategy.(core.AccessTokenStrategy),
				AccessTokenStorage:  storage.(core.AccessTokenStorage),
				AccessTokenLifespan: config.GetAccessTokenLifespan(),
			},
			ScopeStrategy: fosite.HierarchicScopeStrategy,
		},
		CoreValidator: &core.CoreValidator{
			CoreStrategy: strategy.(core.CoreStrategy),
			CoreStorage:  storage.(core.CoreStorage),
		},
	}
}

// OAuth2RefreshTokenGrantFactory creates an OAuth2 refresh grant handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2RefreshTokenGrantFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*refresh.RefreshTokenGrantHandler
		*core.CoreValidator
	}{
		RefreshTokenGrantHandler: &refresh.RefreshTokenGrantHandler{
			AccessTokenStrategy:      strategy.(core.AccessTokenStrategy),
			RefreshTokenStrategy:     strategy.(core.RefreshTokenStrategy),
			RefreshTokenGrantStorage: storage.(refresh.RefreshTokenGrantStorage),
			AccessTokenLifespan:      config.GetAccessTokenLifespan(),
		},
		CoreValidator: &core.CoreValidator{
			CoreStrategy: strategy.(core.CoreStrategy),
			CoreStorage:  storage.(core.CoreStorage),
		},
	}
}

// OAuth2AuthorizeImplicitFactory creates an OAuth2 implicit grant ("authorize implicit flow") handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2AuthorizeImplicitFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*implicit.AuthorizeImplicitGrantTypeHandler
		*core.CoreValidator
	}{
		AuthorizeImplicitGrantTypeHandler: &implicit.AuthorizeImplicitGrantTypeHandler{
			AccessTokenStrategy: strategy.(core.AccessTokenStrategy),
			AccessTokenStorage:  storage.(core.AccessTokenStorage),
			AccessTokenLifespan: config.GetAccessTokenLifespan(),
			ScopeStrategy:       fosite.HierarchicScopeStrategy,
		},
		CoreValidator: &core.CoreValidator{
			CoreStrategy: strategy.(core.CoreStrategy),
			CoreStorage:  storage.(core.CoreStorage),
		},
	}
}

// OAuth2ResourceOwnerPasswordCredentialsFactory creates an OAuth2 resource owner password credentials grant handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2ResourceOwnerPasswordCredentialsFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*owner.ResourceOwnerPasswordCredentialsGrantHandler
		*core.CoreValidator
	}{
		ResourceOwnerPasswordCredentialsGrantHandler: &owner.ResourceOwnerPasswordCredentialsGrantHandler{
			ResourceOwnerPasswordCredentialsGrantStorage: storage.(owner.ResourceOwnerPasswordCredentialsGrantStorage),
			HandleHelper: &core.HandleHelper{
				AccessTokenStrategy: strategy.(core.AccessTokenStrategy),
				AccessTokenStorage:  storage.(core.AccessTokenStorage),
				AccessTokenLifespan: config.GetAccessTokenLifespan(),
			},
			ScopeStrategy: fosite.HierarchicScopeStrategy,
		},
		CoreValidator: &core.CoreValidator{
			CoreStrategy: strategy.(core.CoreStrategy),
			CoreStorage:  storage.(core.CoreStorage),
		},
	}
}
