package compose

import (
	"github.com/ory/fosite/handler/par"
)

func PARStorageFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &par.PushedAuthorizeHandler{
		Storage:                  storage.(par.PARStorage),
		RequestURIPrefix:         config.PushedAuthorizationRequestURIPrefix,
		PARContextLifetime:       config.PushedAuthorizationContextLifespan,
		ScopeStrategy:            config.GetScopeStrategy(),
		AudienceMatchingStrategy: config.GetAudienceStrategy(),
		IsRedirectURISecure:      config.GetRedirectSecureChecker(),
	}
}

// AuthorizePARFactory creates an OAuth2 token revocation handler.
func AuthorizePARFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &par.AuthorizePARHandler{
		Storage:          storage.(par.PARStorage),
		RequestURIPrefix: config.PushedAuthorizationRequestURIPrefix,
	}
}
