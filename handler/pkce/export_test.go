// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"

	"github.com/ory/fosite"
)

func CallValidate(ctx context.Context, challenge, method string, client fosite.Client, handler *Handler) error {
	return handler.validate(ctx, challenge, method, client)
}
