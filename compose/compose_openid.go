package compose

import (
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/oauth2"
	"github.com/ory-am/fosite/handler/openid"
)

// OpenIDConnectExplicit creates an OpenID Connect explicit ("authorize code flow") grant handler. You must add this handler
// *after* you have added an OAuth2 authorize code handler!
func OpenIDConnectExplicit(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*openid.OpenIDConnectExplicitHandler
	}{
		OpenIDConnectExplicitHandler: &openid.OpenIDConnectExplicitHandler{
			OpenIDConnectRequestStorage: storage.(openid.OpenIDConnectRequestStorage),
			IDTokenHandleHelper: &openid.IDTokenHandleHelper{
				IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
			},
		},
	}
}

// OpenIDConnectImplicit creates an OpenID Connect implicit ("implicit flow") grant handler. You must add this handler
// *after* you have added an OAuth2 authorize implicit handler!
func OpenIDConnectImplicit(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*openid.OpenIDConnectImplicitHandler
	}{
		OpenIDConnectImplicitHandler: &openid.OpenIDConnectImplicitHandler{
			AuthorizeImplicitGrantTypeHandler: &oauth2.AuthorizeImplicitGrantTypeHandler{
				AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
				AccessTokenStorage:  storage.(oauth2.AccessTokenStorage),
				AccessTokenLifespan: config.GetAccessTokenLifespan(),
			},
			ScopeStrategy: fosite.HierarchicScopeStrategy,
			IDTokenHandleHelper: &openid.IDTokenHandleHelper{
				IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
			},
		},
	}
}

// OpenIDConnectHybrid creates an OpenID Connect hybrid grant handler. You must add this handler
// *after* you have added an OAuth2 authorize code and implicit authorize handler!
func OpenIDConnectHybrid(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*openid.OpenIDConnectHybridHandler
	}{
		OpenIDConnectHybridHandler: &openid.OpenIDConnectHybridHandler{
			AuthorizeExplicitGrantHandler: &oauth2.AuthorizeExplicitGrantHandler{
				AccessTokenStrategy:       strategy.(oauth2.AccessTokenStrategy),
				RefreshTokenStrategy:      strategy.(oauth2.RefreshTokenStrategy),
				AuthorizeCodeStrategy:     strategy.(oauth2.AuthorizeCodeStrategy),
				AuthorizeCodeGrantStorage: storage.(oauth2.AuthorizeCodeGrantStorage),
				AuthCodeLifespan:          config.GetAuthorizeCodeLifespan(),
				AccessTokenLifespan:       config.GetAccessTokenLifespan(),
			},
			ScopeStrategy: fosite.HierarchicScopeStrategy,
			AuthorizeImplicitGrantTypeHandler: &oauth2.AuthorizeImplicitGrantTypeHandler{
				AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
				AccessTokenStorage:  storage.(oauth2.AccessTokenStorage),
				AccessTokenLifespan: config.GetAccessTokenLifespan(),
			},
			IDTokenHandleHelper: &openid.IDTokenHandleHelper{
				IDTokenStrategy: strategy.(openid.OpenIDConnectTokenStrategy),
			},
		},
	}
}
