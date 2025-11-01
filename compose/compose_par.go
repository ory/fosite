// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/par"
)

// PushedAuthorizeHandlerFactory creates the basic PAR handler
func PushedAuthorizeHandlerFactory(config fosite.Configurator, storage fosite.Storage, _ interface{}) interface{} {
	return &par.PushedAuthorizeHandler{
		Storage: storage.(fosite.PARStorageProvider),
		Config:  config,
	}
}
