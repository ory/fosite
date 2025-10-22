// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"

	"github.com/ory/fosite"
)

type (
	RequestStorage interface {
		GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error)
		CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error
		DeletePKCERequestSession(ctx context.Context, signature string) error
	}
	RequestStorageProvider interface {
		PKCERequestStorage() RequestStorage
	}
)
