// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package verifiable

import (
	"context"

	"github.com/ory/fosite"
)

type Storage interface {

	// GetPreAuthorizeSession returns pre-authorize session
	// When revokeSession is true, after successful retrieval of the session, the session should be deleted right away
	GetPreAuthorizeSession(ctx context.Context, signature string, session fosite.Session, revokeSession bool) (request fosite.PreAuthorizeRequester, err error)
}
