package oidc

import (
	"github.com/ory-am/common/pkg"
	"golang.org/x/net/context"
)

var ErrNoSessionFound = pkg.ErrNotFound

type OpenIDConnectRequestStorage interface {
	// CreateOpenIDConnectSession creates an open id connect session
	// for a given authorize code. This is relevant for explicit open id connect flow.
	CreateOpenIDConnectSession(ctx context.Context, authorizeCode string) error

	// IsOpenIDConnectSession returns
	// - nil if a session was found,
	// - ErrNoSessionFound if no session was found
	// - or an arbitrary error if an error occurred.
	IsOpenIDConnectSession(ctx context.Context, authorizeCode string) error

	// DeleteOpenIDConnectSession removes an open id connect session from the store.
	DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error
}
