// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package verifiable

import (
	"context"

	"github.com/ory/fosite"
)

type Storage interface {

	// GetPreAuthorizeSession returns pre-authorize code session
	// since the specification says pre-authorize code can only be used once,
	// implementation of this method may delete the session right away from persistence storage
	GetPreAuthorizeSession(ctx context.Context, signature string, session fosite.Session) (request fosite.PreAuthorizeRequester, err error)
}
