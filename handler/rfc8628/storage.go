// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

// RFC8628CoreStorage is the storage needed for the DeviceAuthHandler
type RFC8628CoreStorage interface {
	DeviceAuthStorage
	oauth2.AccessTokenStorage
	oauth2.RefreshTokenStorage
}

// DeviceAuthStorage handles the device auth session storage
type DeviceAuthStorage interface {
	// CreateDeviceAuthSession stores the device auth request session.
	CreateDeviceAuthSession(ctx context.Context, deviceCodeSignature, userCodeSignature string, request fosite.Requester) (err error)

	// GetDeviceCodeSession hydrates the session based on the given device code and returns the device request.
	// If the device code has been invalidated with `InvalidateDeviceCodeSession`, this
	// method should return the ErrInvalidatedDeviceCode error.
	//
	// Make sure to also return the fosite.Requester value when returning the fosite.ErrInvalidatedDeviceCode error!
	GetDeviceCodeSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error)

	// InvalidateDeviceCodeSession is called when a device code is being used. The state of the device
	// code should be set to invalid and consecutive requests to GetDeviceCodeSession should return the
	// ErrInvalidatedDeviceCode error.
	InvalidateDeviceCodeSession(ctx context.Context, signature string) (err error)
}
