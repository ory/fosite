// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/rfc8628"
)

// RFC8628DeviceFactory creates an OAuth2 device code grant ("Device Authorization Grant") handler and registers
// an user code, device code, access token and a refresh token validator.
func RFC8628DeviceFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc8628.DeviceAuthHandler{
		Strategy: strategy.(rfc8628.RFC8628CodeStrategy),
		Storage:  storage.(rfc8628.RFC8628CodeStorage),
		Config:   config,
	}
}
