package compose

import (
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/rfc7523"
)

// RFC7523AssertionGrantFactory creates an OAuth2 Authorize JWT Grant (using JWTs as Authorization Grants) handler
// and registers an access token, refresh token and authorize code validator.
func RFC7523AssertionGrantFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &rfc7523.Handler{
		Storage:                  storage.(rfc7523.RFC7523KeyStorage),
		ScopeStrategy:            config.GetScopeStrategy(),
		AudienceMatchingStrategy: config.GetAudienceStrategy(),
		TokenURL:                 config.TokenURL,
		SkipClientAuth:           config.GrantTypeJWTBearerCanSkipClientAuth,
		JWTIDOptional:            config.GrantTypeJWTBearerIDOptional,
		JWTIssuedDateOptional:    config.GrantTypeJWTBearerIssuedDateOptional,
		JWTMaxDuration:           config.GetJWTMaxDuration(),
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(oauth2.AccessTokenStorage),
			AccessTokenLifespan: config.GetAccessTokenLifespan(),
		},
	}
}
