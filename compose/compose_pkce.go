package compose

import (
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"
)

// OAuth2PKCEFactory creates a PKCE handler.
func OAuth2PKCEFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &pkce.Handler{
		AuthorizeCodeStrategy: strategy.(oauth2.AuthorizeCodeStrategy),
		CoreStorage:           storage.(oauth2.CoreStorage),
		Force:                 config.EnforcePKCE,
		EnablePlainChallengeMethod: config.EnablePKCEPlainChallengeMethod,
	}
}
