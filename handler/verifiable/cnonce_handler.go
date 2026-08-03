// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package verifiable

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

type CredentialNonceHandler struct {
	Config interface {
		fosite.VerifiableCredentialsNonceLifespanProvider
	}
}

var _ fosite.TokenEndpointHandler = (*CredentialNonceHandler)(nil)

// HandleTokenEndpointRequest handles an authorize request. If the handler is not responsible for handling
// the request, this method should return ErrUnknownRequest and otherwise handle the request.
func (c *CredentialNonceHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	return nil
}

// PopulateTokenEndpointResponse is responsible for setting return values and should only be executed if
// the handler's HandleTokenEndpointRequest did not return ErrUnknownRequest.
func (c *CredentialNonceHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	sess, ok := request.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to generate credential nonce because the session is not of the right type."))
	}

	// generate the nonce
	nonce, err := GenerateNonce()
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to generate credential nonce."))
	}

	lifespan := c.Config.GetVerifiableCredentialsNonceLifespan(ctx)

	// associate it with the session
	sess.SetCredentialNonce(nonce, time.Now().Add(lifespan))

	// return it as part of token response
	response.SetExtra("c_nonce", nonce)
	response.SetExtra("c_nonce_expires_in", int64(lifespan.Seconds()))
	return nil
}

func (c *CredentialNonceHandler) CanSkipClientAuth(context.Context, fosite.AccessRequester) bool {
	return false
}

func (c *CredentialNonceHandler) CanHandleTokenEndpointRequest(_ context.Context, requester fosite.AccessRequester) bool {
	if c, ok := requester.GetClient().(fosite.CredentialIssuerClient); ok {
		return c.IsCredentialIssuerClient()
	}
	return false
}
