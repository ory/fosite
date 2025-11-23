// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/rfc8693"
)

// RFC8693TokenExchangeFactory creates an OAuth2 Token Exchange handler (RFC 8693)
// and registers an access token validator.
func RFC8693TokenExchangeFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc8693.Handler{
		Config:               config,
		AccessTokenStrategy:  strategy.(oauth2.AccessTokenStrategy),
		AccessTokenStorage:   storage.(oauth2.AccessTokenStorage),
		RefreshTokenStrategy: strategy.(oauth2.RefreshTokenStrategy),
		RefreshTokenStorage:  storage.(oauth2.RefreshTokenStorage),
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStrategy: strategy.(oauth2.AccessTokenStrategy),
			AccessTokenStorage:  storage.(oauth2.AccessTokenStorage),
			Config:              config,
		},
	}
}
