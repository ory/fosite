// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package verifiable

import (
	"context"

	"github.com/ory/fosite"
)

var _ fosite.AuthorizeEndpointHandler = (*IssuerStateHandler)(nil)

// IssuerStateHandler handles additional 'issuer_state' request parameter in credential issuer context
type IssuerStateHandler struct{}

func (h *IssuerStateHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	client, ok := ar.GetClient().(fosite.CredentialIssuerClient)
	if !ok || !client.IsCredentialIssuerClient() {
		return nil // do nothing
	}

	sess, ok := ar.GetSession().(Session)
	if !ok {
		return nil
	}

	if is := ar.GetRequestForm().Get("issuer_state"); len(is) > 0 {
		sess.SetIssuerState(is) // associate it with the session
	}
	return nil
}
