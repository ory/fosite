/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package oauth2

import (
	"context"

	"github.com/ory/fosite"
)

type CoreStorage interface {
	AuthorizeCodeStorage
	AccessTokenStorage
	RefreshTokenStorage
}

// AuthorizeCodeStorage handles storage requests related to authorization codes.
type AuthorizeCodeStorage interface {
	// GetAuthorizeCodeSession stores the authorization request for a given authorization code.
	CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) (err error)

	// GetAuthorizeCodeSession hydrates the session based on the given code and returns the authorization request.
	// If the authorization code has been invalidated with `InvalidateAuthorizeCodeSession`, this
	// method should return the ErrInvalidatedAuthorizeCode error.
	//
	// Make sure to also return the fosite.Requester value when returning the fosite.ErrInvalidatedAuthorizeCode error!
	GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (request fosite.Requester, err error)

	// InvalidateAuthorizeCodeSession is called when an authorize code is being used. The state of the authorization
	// code should be set to invalid and consecutive requests to GetAuthorizeCodeSession should return the
	// ErrInvalidatedAuthorizeCode error.
	InvalidateAuthorizeCodeSession(ctx context.Context, code string) (err error)
}

// DeviceAuthorizeStorage handles storage requests related to device authorization codes as part of the Device Authorisation Grant.

// type DeviceAuthorizeStorage interface {
// 	CreateDeviceAuthorizeSession(ctx context.Context, deviceCode string, userCode string, request fosite.Requester) (err error)

// 	GetDeviceAuthorizeSession(ctx context.Context, deviceCode string, session fosite.Session) (request fosite.Requester, err error)
// }

type AccessTokenStorage interface {
	CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error)

	GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error)

	DeleteAccessTokenSession(ctx context.Context, signature string) (err error)
}

type RefreshTokenStorage interface {
	CreateRefreshTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error)

	GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error)

	DeleteRefreshTokenSession(ctx context.Context, signature string) (err error)
}

type DeviceCodeStorage interface {
	CreateDeviceCodeSession(ctx context.Context, signature string, request fosite.Requester) (err error)
	UpdateDeviceCodeSession(ctx context.Context, signature string, request fosite.Requester) (err error)

	// InvalidateDeviceCodeSession is called when a device code is being used. The state of the device code should
	// be set to invalid and consecutive requests to GetDeviceCodeSession should return the
	// ErrInvalidatedAuthorizeCode error.
	// InvalidateDeviceCodeSession(ctx context.Context, code string) (err error)

	GetDeviceCodeSession(ctx context.Context, code string, session fosite.Session) (request fosite.DeviceAuthorizeRequester, err error)
	GetDeviceCodeSessionByRequestID(ctx context.Context, requestID string, session fosite.Session) (request fosite.DeviceAuthorizeRequester, err error)
}

type UserCodeStorage interface {
	CreateUserCodeSession(ctx context.Context, signature string, request fosite.Requester) (err error)

	GetUserCodeSession(ctx context.Context, code string, session fosite.Session) (request fosite.Requester, err error)

	// InvalidateUserCodeSession is called when a user code has been used/claimed. The state of the user code should
	// be set to invalid and consecutive requests to GetUserCodeSession should return the ErrInvalidatedUserCode error.
	InvalidateUserCodeSession(ctx context.Context, code string) (err error)
}