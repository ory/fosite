package compose

import (
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/oauth2"
)

// OAuth2AuthorizeExplicitFactory creates an OAuth2 authorize code grant ("authorize explicit flow") handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2AuthorizeExplicitFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*oauth2.AuthorizeExplicitGrantHandler
		*oauth2.CoreValidator
	}{
		AuthorizeExplicitGrantHandler: &oauth2.AuthorizeExplicitGrantHandler{
			AccessTokenStrategy:       strategy.(oauth2.AccessTokenStrategy),
			RefreshTokenStrategy:      strategy.(oauth2.RefreshTokenStrategy),
			AuthorizeCodeStrategy:     strategy.(oauth2.AuthorizeCodeStrategy),
			AuthorizeCodeGrantStorage: storage.(oauth2.AuthorizeCodeGrantStorage),
			AuthCodeLifespan:          config.GetAuthorizeCodeLifespan(),
			AccessTokenLifespan:       config.GetAccessTokenLifespan(),
			ScopeStrategy:             fosite.HierarchicScopeStrategy,
		},
		CoreValidator: &oauth2.CoreValidator{
			CoreStrategy:  strategy.(oauth2.CoreStrategy),
			CoreStorage:   storage.(oauth2.CoreStorage),
			ScopeStrategy: fosite.HierarchicScopeStrategy,
		},
	}
}

// OAuth2ClientCredentialsGrantFactory creates an OAuth2 client credentials grant handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2ClientCredentialsGrantFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*oauth2.ClientCredentialsGrantHandler
		*oauth2.CoreValidator
	}{
		ClientCredentialsGrantHandler: &oauth2.ClientCredentialsGrantHandler{
			HandleHelper: &oauth2.HandleHelper{
				AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
				AccessTokenStorage:  storage.(oauth2.AccessTokenStorage),
				AccessTokenLifespan: config.GetAccessTokenLifespan(),
			},
			ScopeStrategy: fosite.HierarchicScopeStrategy,
		},
		CoreValidator: &oauth2.CoreValidator{
			CoreStrategy:  strategy.(oauth2.CoreStrategy),
			CoreStorage:   storage.(oauth2.CoreStorage),
			ScopeStrategy: fosite.HierarchicScopeStrategy,
		},
	}
}

// OAuth2RefreshTokenGrantFactory creates an OAuth2 refresh grant handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2RefreshTokenGrantFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*oauth2.RefreshTokenGrantHandler
		*oauth2.CoreValidator
	}{
		RefreshTokenGrantHandler: &oauth2.RefreshTokenGrantHandler{
			AccessTokenStrategy:      strategy.(oauth2.AccessTokenStrategy),
			RefreshTokenStrategy:     strategy.(oauth2.RefreshTokenStrategy),
			RefreshTokenGrantStorage: storage.(oauth2.RefreshTokenGrantStorage),
			AccessTokenLifespan:      config.GetAccessTokenLifespan(),
		},
		CoreValidator: &oauth2.CoreValidator{
			CoreStrategy:  strategy.(oauth2.CoreStrategy),
			CoreStorage:   storage.(oauth2.CoreStorage),
			ScopeStrategy: fosite.HierarchicScopeStrategy,
		},
	}
}

// OAuth2AuthorizeImplicitFactory creates an OAuth2 implicit grant ("authorize implicit flow") handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2AuthorizeImplicitFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*oauth2.AuthorizeImplicitGrantTypeHandler
		*oauth2.CoreValidator
	}{
		AuthorizeImplicitGrantTypeHandler: &oauth2.AuthorizeImplicitGrantTypeHandler{
			AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(oauth2.AccessTokenStorage),
			AccessTokenLifespan: config.GetAccessTokenLifespan(),
			ScopeStrategy:       fosite.HierarchicScopeStrategy,
		},
		CoreValidator: &oauth2.CoreValidator{
			CoreStrategy:  strategy.(oauth2.CoreStrategy),
			CoreStorage:   storage.(oauth2.CoreStorage),
			ScopeStrategy: fosite.HierarchicScopeStrategy,
		},
	}
}

// OAuth2ResourceOwnerPasswordCredentialsFactory creates an OAuth2 resource owner password credentials grant handler and registers
// an access token, refresh token and authorize code validator.
func OAuth2ResourceOwnerPasswordCredentialsFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*oauth2.ResourceOwnerPasswordCredentialsGrantHandler
		*oauth2.CoreValidator
	}{
		ResourceOwnerPasswordCredentialsGrantHandler: &oauth2.ResourceOwnerPasswordCredentialsGrantHandler{
			ResourceOwnerPasswordCredentialsGrantStorage: storage.(oauth2.ResourceOwnerPasswordCredentialsGrantStorage),
			HandleHelper: &oauth2.HandleHelper{
				AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
				AccessTokenStorage:  storage.(oauth2.AccessTokenStorage),
				AccessTokenLifespan: config.GetAccessTokenLifespan(),
			},
			ScopeStrategy: fosite.HierarchicScopeStrategy,
		},
		CoreValidator: &oauth2.CoreValidator{
			CoreStrategy:  strategy.(oauth2.CoreStrategy),
			CoreStorage:   storage.(oauth2.CoreStorage),
			ScopeStrategy: fosite.HierarchicScopeStrategy,
		},
	}
}
