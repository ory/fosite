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
	DeviceCodeStorage
	UserCodeStorage
	oauth2.AccessTokenStorage
	oauth2.RefreshTokenStorage
}

// DeviceCodeStorage handles the device_code storage
type DeviceCodeStorage interface {
	// CreateDeviceCodeSession stores the device request for a given device code.
	CreateDeviceCodeSession(ctx context.Context, signature string, request fosite.Requester) (err error)

	// GetDeviceCodeSession hydrates the session based on the given device code and returns the device request.
	// If the device code has been invalidated with `InvalidateDeviceCodeSession`, this
	// method should return the ErrInvalidatedDeviceCode error.
	//
	// Make sure to also return the fosite.Requester value when returning the fosite.ErrInvalidatedDeviceCode error!
	GetDeviceCodeSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error)

	// InvalidateDeviceCodeSession is called when an device code is being used. The state of the user
	// code should be set to invalid and consecutive requests to GetDeviceCodeSession should return the
	// ErrInvalidatedDeviceCode error.
	InvalidateDeviceCodeSession(ctx context.Context, signature string) (err error)
}

// UserCodeStorage handles the user_code storage
type UserCodeStorage interface {
	// CreateUserCodeSession stores the device request for a given user code.
	CreateUserCodeSession(ctx context.Context, signature string, request fosite.Requester) (err error)

	// GetUserCodeSession hydrates the session based on the given user code and returns the device request.
	// If the user code has been invalidated with `InvalidateUserCodeSession`, this
	// method should return the ErrInvalidatedUserCode error.
	//
	// Make sure to also return the fosite.Requester value when returning the fosite.ErrInvalidatedUserCode error!
	GetUserCodeSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error)

	// InvalidateUserCodeSession is called when an user code is being used. The state of the user
	// code should be set to invalid and consecutive requests to GetUserCodeSession should return the
	// ErrInvalidatedUserCode error.
	InvalidateUserCodeSession(ctx context.Context, signature string) (err error)
}
