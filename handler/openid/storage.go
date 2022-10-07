// Copyright © 2022 Ory Corp

package openid

import (
	"context"

	"github.com/ory/fosite"
)

var ErrNoSessionFound = fosite.ErrNotFound

type OpenIDConnectRequestStorage interface {
	// CreateOpenIDConnectSession creates an open id connect session
	// for a given authorize code. This is relevant for explicit open id connect flow.
	CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error

	// GetOpenIDConnectSession returns error
	// - nil if a session was found,
	// - ErrNoSessionFound if no session was found
	// - or an arbitrary error if an error occurred.
	GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error)

	// Deprecated: DeleteOpenIDConnectSession is not called from anywhere.
	// Originally, it should remove an open id connect session from the store.
	DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error
}
