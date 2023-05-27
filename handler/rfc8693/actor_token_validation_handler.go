// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
	"github.com/pkg/errors"
)

type ActorTokenValidationHandler struct{}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *ActorTokenValidationHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	client := request.GetClient()
	session, _ := request.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	// Validate that the actor or client is allowed to make this request
	subjectTokenObject := session.GetSubjectToken()
	if mayAct, _ := subjectTokenObject["may_act"].(map[string]interface{}); mayAct != nil {
		actorTokenObject := session.GetActorToken()
		if actorTokenObject == nil {
			actorTokenObject = map[string]interface{}{
				"sub":       client.GetID(),
				"client_id": client.GetID(),
			}
		}

		for k, v := range mayAct {
			if actorTokenObject[k] != v {
				return errors.WithStack(fosite.ErrInvalidRequest.WithHint("The actor or client is not authorized to act on behalf of the subject."))
			}
		}
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *ActorTokenValidationHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, responder fosite.AccessResponder) error {
	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *ActorTokenValidationHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *ActorTokenValidationHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "password".
	return requester.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:token-exchange")
}
