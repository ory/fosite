package compose

import (
	"github.com/ory/fosite/handler/par"
)

// PushedAuthorizeHandlerFactory creates the basic PAR handler
func PushedAuthorizeHandlerFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &par.PushedAuthorizeHandler{
		Storage:                  storage,
		RequestURIPrefix:         config.PushedAuthorizationRequestURIPrefix,
		PARContextLifetime:       config.PushedAuthorizationContextLifespan,
		ScopeStrategy:            config.GetScopeStrategy(),
		AudienceMatchingStrategy: config.GetAudienceStrategy(),
		IsRedirectURISecure:      config.GetRedirectSecureChecker(),
	}
}
