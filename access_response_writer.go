// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"

	"github.com/ory/x/errorsx"

	"github.com/pkg/errors"
)

func (f *Fosite) NewAccessResponse(ctx context.Context, requester AccessRequester) (AccessResponder, error) {
	var err error
	var tk TokenEndpointHandler

	response := NewAccessResponse()

	ctx = context.WithValue(ctx, AccessRequestContextKey, requester)
	ctx = context.WithValue(ctx, AccessResponseContextKey, response)

	for _, tk = range f.Config.GetTokenEndpointHandlers(ctx) {
		if err = tk.PopulateTokenEndpointResponse(ctx, requester, response); err == nil {
			// do nothing
		} else if errors.Is(err, ErrUnknownRequest) {
			// do nothing
		} else if err != nil {
			return nil, err
		}
	}

	if response.GetAccessToken() == "" || response.GetTokenType() == "" {
		return nil, errorsx.WithStack(ErrServerError.
			WithHint("An internal server occurred while trying to complete the request.").
			WithDebug("Access token or token type not set by TokenEndpointHandlers.").
			WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(requester)))
	}

	return response, nil
}
