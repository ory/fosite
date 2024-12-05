// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
	"github.com/pkg/errors"
)

var _ fosite.TokenEndpointHandler = (*TokenExchangeGrantHandler)(nil)

// TokenExchangeGrantHandler is the grant handler for RFC8693
type TokenExchangeGrantHandler struct {
	Config fosite.Configurator
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *TokenExchangeGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	client := request.GetClient()
	if client.IsPublic() {
		return errors.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is marked as public and is thus not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:token-exchange\"."))
	}

	// Check whether client is allowed to use token exchange
	if !client.GetGrantTypes().Has("urn:ietf:params:oauth:grant-type:token-exchange") {
		return errors.WithStack(fosite.ErrUnauthorizedClient.WithHintf(
			"The OAuth 2.0 Client is not allowed to use authorization grant \"%s\".", "urn:ietf:params:oauth:grant-type:token-exchange"))
	}

	session, _ := request.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	teConfig, _ := c.Config.(fosite.RFC8693ConfigProvider)
	if teConfig == nil {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to perform token exchange because the config is not of the right type."))
	}

	form := request.GetRequestForm()
	configTypesSupported := teConfig.GetTokenTypes(ctx)
	var supportedSubjectTypes, supportedActorTypes, supportedRequestTypes fosite.Arguments
	actorTokenRequired := false
	if teClient, ok := client.(Client); ok {
		supportedRequestTypes = fosite.Arguments(teClient.GetSupportedRequestTokenTypes())
		supportedActorTypes = fosite.Arguments(teClient.GetSupportedActorTokenTypes())
		supportedSubjectTypes = fosite.Arguments(teClient.GetSupportedSubjectTokenTypes())
		actorTokenRequired = teClient.ActorTokenRequired()
	}

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	subject_token
	//		REQUIRED.  A security token that represents the identity of the
	//		party on behalf of whom the request is being made.  Typically, the
	//		subject of this token will be the subject of the security token
	//		issued in response to the request.
	subjectToken := form.Get("subject_token")
	if subjectToken == "" {
		return errors.WithStack(fosite.ErrInvalidRequest.WithHintf("Mandatory parameter \"%s\" is missing.", "subject_token"))
	}

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	subject_token_type
	//		REQUIRED.  An identifier, as described in Section 3, that
	//		indicates the type of the security token in the "subject_token"
	//		parameter.
	subjectTokenType := form.Get("subject_token_type")
	if subjectTokenType == "" {
		return errors.WithStack(fosite.ErrInvalidRequest.WithHintf("Mandatory parameter \"%s\" is missing.", "subject_token_type"))
	}

	if tt := configTypesSupported[subjectTokenType]; tt == nil {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("\"%s\" token type is not supported as a \"%s\".", subjectTokenType, "subject_token_type"))
	}

	if len(supportedSubjectTypes) > 0 && !supportedSubjectTypes.Has(subjectTokenType) {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf(
			"The OAuth 2.0 client is not allowed to use \"%s\" as \"%s\".", subjectTokenType, "subject_token_type"))
	}

	// From https://tools.ietf.org/html/rfc8693#section-2.1:
	//
	//	actor_token
	//		OPTIONAL . A security token that represents the identity of the acting party.
	//		Typically, this will be the party that is authorized to use the requested security
	//		token and act on behalf of the subject.
	actorToken := form.Get("actor_token")
	actorTokenType := form.Get("actor_token_type")
	if actorToken != "" {
		// From https://tools.ietf.org/html/rfc8693#section-2.1:
		//
		//	actor_token_type
		//		An identifier, as described in Section 3, that indicates the type of the security token
		//		in the actor_token parameter. This is REQUIRED when the actor_token parameter is present
		//		in the request but MUST NOT be included otherwise.
		if actorTokenType == "" {
			return errors.WithStack(fosite.ErrInvalidRequest.WithHintf("\"actor_token_type\" is empty even though the \"actor_token\" is not empty."))
		}

		if tt := configTypesSupported[actorTokenType]; tt == nil {
			return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf(
				"\"%s\" token type is not supported as a \"%s\".", actorTokenType, "actor_token_type"))
		}

		if len(supportedActorTypes) > 0 && !supportedActorTypes.Has(actorTokenType) {
			return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf(
				"The OAuth 2.0 client is not allowed to use \"%s\" as \"%s\".", actorTokenType, "actor_token_type"))
		}
	} else if actorTokenType != "" {
		return errors.WithStack(fosite.ErrInvalidRequest.WithHintf("\"actor_token_type\" is not empty even though the \"actor_token\" is empty."))
	} else if actorTokenRequired {
		return errors.WithStack(fosite.ErrInvalidRequest.WithHintf("The OAuth 2.0 client must provide an actor token."))
	}

	// check if supported
	requestedTokenType := form.Get("requested_token_type")
	if requestedTokenType == "" {
		requestedTokenType = teConfig.GetDefaultRequestedTokenType(ctx)
	}

	if tt := configTypesSupported[requestedTokenType]; tt == nil {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf(
			"\"%s\" token type is not supported as a \"%s\".", requestedTokenType, "requested_token_type"))
	}

	if len(supportedRequestTypes) > 0 && !supportedRequestTypes.Has(requestedTokenType) {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("The OAuth 2.0 client is not allowed to use \"%s\" as \"%s\".", requestedTokenType, "requested_token_type"))
	}

	// Check scope
	openIDIndex := -1
	for i, scope := range request.GetRequestedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(client.GetScopes(), scope) {
			return errors.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}

		// making an assumption here that scope=openid is only present once.
		// scope=openid makes no sense in the token exchange flow, so we are going
		// to remove it.
		if scope == "openid" {
			openIDIndex = i
		}
	}

	if openIDIndex > -1 {
		requestedScopes := request.GetRequestedScopes()
		requestedScopes[openIDIndex] = requestedScopes[len(requestedScopes)-1]
		requestedScopes = requestedScopes[:len(requestedScopes)-1]

		request.SetRequestedScopes(requestedScopes)
	}

	// Check audience
	if err := c.Config.GetAudienceStrategy(ctx)(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		// TODO: Need to convert to using invalid_target
		return err
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *TokenExchangeGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	session, _ := request.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	teConfig, _ := c.Config.(fosite.RFC8693ConfigProvider)
	if teConfig == nil {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to perform token exchange because the config is not of the right type."))
	}

	form := request.GetRequestForm()
	requestedTokenType := form.Get("requested_token_type")
	if requestedTokenType == "" {
		requestedTokenType = teConfig.GetDefaultRequestedTokenType(ctx)
	}

	configTypesSupported := teConfig.GetTokenTypes(ctx)
	if tt := configTypesSupported[requestedTokenType]; tt == nil {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf(
			"\"%s\" token type is not supported as a \"%s\".", requestedTokenType, "requested_token_type"))
	}

	// chain `act` if necessary
	subjectTokenObject := session.GetSubjectToken()
	if mayAct, _ := subjectTokenObject["may_act"].(map[string]interface{}); mayAct != nil {
		if subjectActor, _ := subjectTokenObject["act"].(map[string]interface{}); subjectActor != nil {
			mayAct["act"] = subjectActor
		}

		session.SetAct(mayAct)
	}

	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *TokenExchangeGrantHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *TokenExchangeGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	return requester.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:token-exchange")
}
