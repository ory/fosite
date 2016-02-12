package oidc

import "github.com/ory-am/common/pkg"

var ErrNoSessionFound = pkg.ErrNotFound

type OpenIDConnectRequestStorage interface {
	// CreateOpenIDConnectSession creates an open id connect session
	// for a given authorize code. This is relevant for explicit open id connect flow.
	CreateOpenIDConnectSession(authorizeCode string) error

	// IsOpenIDConnectSession returns
	// - nil if a session was found,
	// - ErrNoSessionFound if no session was found
	// - or an arbitrary error if an error occurred.
	IsOpenIDConnectSession(authorizeCode string) error

	// DeleteOpenIDConnectSession removes an open id connect session from the store.
	DeleteOpenIDConnectSession(authorizeCode string) error
}
