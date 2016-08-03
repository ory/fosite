package compose

import (
	"github.com/ory-am/fosite/handler/core"
	cex "github.com/ory-am/fosite/handler/core/explicit"
	cim "github.com/ory-am/fosite/handler/core/implicit"
	"github.com/ory-am/fosite/handler/oidc"
	"github.com/ory-am/fosite/handler/oidc/explicit"
	"github.com/ory-am/fosite/handler/oidc/hybrid"
	"github.com/ory-am/fosite/handler/oidc/implicit"
)

// OpenIDConnectExplicit creates an OpenID Connect explicit ("authorize code flow") grant handler. You must add this handler
// *after* you have added an OAuth2 authorize code handler!
func OpenIDConnectExplicit(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*explicit.OpenIDConnectExplicitHandler
	}{
		OpenIDConnectExplicitHandler: &explicit.OpenIDConnectExplicitHandler{
			OpenIDConnectRequestStorage: storage.(oidc.OpenIDConnectRequestStorage),
			IDTokenHandleHelper: &oidc.IDTokenHandleHelper{
				IDTokenStrategy: strategy.(oidc.OpenIDConnectTokenStrategy),
			},
		},
	}
}

// OpenIDConnectImplicit creates an OpenID Connect implicit ("implicit flow") grant handler. You must add this handler
// *after* you have added an OAuth2 authorize implicit handler!
func OpenIDConnectImplicit(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*implicit.OpenIDConnectImplicitHandler
	}{
		OpenIDConnectImplicitHandler: &implicit.OpenIDConnectImplicitHandler{
			AuthorizeImplicitGrantTypeHandler: &cim.AuthorizeImplicitGrantTypeHandler{
				AccessTokenStrategy: strategy.(core.AccessTokenStrategy),
				AccessTokenStorage:  storage.(core.AccessTokenStorage),
				AccessTokenLifespan: config.GetAccessTokenLifespan(),
			},
			IDTokenHandleHelper: &oidc.IDTokenHandleHelper{
				IDTokenStrategy: strategy.(oidc.OpenIDConnectTokenStrategy),
			},
		},
	}
}

// OpenIDConnectHybrid creates an OpenID Connect hybrid grant handler. You must add this handler
// *after* you have added an OAuth2 authorize code and implicit authorize handler!
func OpenIDConnectHybrid(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &struct {
		*hybrid.OpenIDConnectHybridHandler
	}{
		OpenIDConnectHybridHandler: &hybrid.OpenIDConnectHybridHandler{
			AuthorizeExplicitGrantHandler: &cex.AuthorizeExplicitGrantHandler{
				AccessTokenStrategy:       strategy.(core.AccessTokenStrategy),
				RefreshTokenStrategy:      strategy.(core.RefreshTokenStrategy),
				AuthorizeCodeStrategy:     strategy.(core.AuthorizeCodeStrategy),
				AuthorizeCodeGrantStorage: storage.(cex.AuthorizeCodeGrantStorage),
				AuthCodeLifespan:          config.GetAuthorizeCodeLifespan(),
				AccessTokenLifespan:       config.GetAccessTokenLifespan(),
			},
			AuthorizeImplicitGrantTypeHandler: &cim.AuthorizeImplicitGrantTypeHandler{
				AccessTokenStrategy: strategy.(core.AccessTokenStrategy),
				AccessTokenStorage:  storage.(core.AccessTokenStorage),
				AccessTokenLifespan: config.GetAccessTokenLifespan(),
			},
			IDTokenHandleHelper: &oidc.IDTokenHandleHelper{
				IDTokenStrategy: strategy.(oidc.OpenIDConnectTokenStrategy),
			},
		},
	}
}
