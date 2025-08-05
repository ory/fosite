// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/x/errorsx"
)

// RFC 8693 Token Exchange grant type
const GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// RFC 8693 Token types
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
)

// Handler implements RFC 8693 OAuth 2.0 Token Exchange
type Handler struct {
	Storage RFC8693Storage

	Config interface {
		fosite.AccessTokenLifespanProvider
		fosite.RefreshTokenLifespanProvider
		fosite.ScopeStrategyProvider
		fosite.AudienceStrategyProvider
		fosite.TokenExchangeEnabledProvider
		fosite.TokenExchangeTokenTypesProvider
	}

	*oauth2.HandleHelper
}

var _ fosite.TokenEndpointHandler = (*Handler)(nil)

// CanHandleTokenEndpointRequest returns true if the grant type is token exchange
func (c *Handler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(GrantTypeTokenExchange)
}

// CanSkipClientAuth returns false as client authentication is required for token exchange
func (c *Handler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

// HandleTokenEndpointRequest handles the token exchange request
func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	if !c.Config.GetTokenExchangeEnabled(ctx) {
		return errorsx.WithStack(fosite.ErrUnsupportedGrantType.WithHint("Token exchange is disabled."))
	}

	client := request.GetClient()
	if client == nil {
		return errorsx.WithStack(fosite.ErrInvalidClient.WithHint("Client authentication failed."))
	}

	form := request.GetRequestForm()

	// Required parameters
	subjectToken := form.Get("subject_token")
	if subjectToken == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("The subject_token parameter is required."))
	}

	subjectTokenType := form.Get("subject_token_type")
	if subjectTokenType == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("The subject_token_type parameter is required."))
	}

	// Validate subject token type
	if !c.isValidTokenType(ctx, subjectTokenType) {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("The subject_token_type is not supported."))
	}

	// Optional parameters
	requestedTokenType := form.Get("requested_token_type")
	if requestedTokenType != "" && !c.isValidTokenType(ctx, requestedTokenType) {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("The requested_token_type is not supported."))
	}

	audience := form.Get("audience")
	scope := form.Get("scope")
	resource := form.Get("resource")

	// Optional actor token parameters
	actorToken := form.Get("actor_token")
	actorTokenType := form.Get("actor_token_type")

	if actorToken != "" && actorTokenType == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("The actor_token_type parameter is required when actor_token is provided."))
	}

	if actorTokenType != "" && !c.isValidTokenType(ctx, actorTokenType) {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("The actor_token_type is not supported."))
	}

	// Validate the subject token
	subjectTokenInfo, err := c.Storage.ValidateSubjectToken(ctx, subjectToken, subjectTokenType, client)
	if err != nil {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("The subject_token is invalid.").WithWrap(err))
	}

	// Validate the actor token if provided
	var actorTokenInfo *TokenInfo
	if actorToken != "" {
		actorTokenInfo, err = c.Storage.ValidateActorToken(ctx, actorToken, actorTokenType, client)
		if err != nil {
			return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("The actor_token is invalid.").WithWrap(err))
		}
	}

	// Handle scope parameter
	requestedScopes := fosite.Arguments{}
	if scope != "" {
		requestedScopes = fosite.RemoveEmpty(strings.Split(scope, " "))
	} else {
		// If no scope is specified, use the scope from the subject token
		requestedScopes = subjectTokenInfo.Scopes
	}

	// Validate scopes
	for _, requestedScope := range requestedScopes {
		if !c.Config.GetScopeStrategy(ctx)(subjectTokenInfo.Scopes, requestedScope) {
			return errorsx.WithStack(fosite.ErrInvalidScope.WithHintf("The requested scope '%s' was not granted by the subject token.", requestedScope))
		}
	}

	// Handle audience parameter
	requestedAudiences := fosite.Arguments{}
	if audience != "" {
		requestedAudiences = fosite.RemoveEmpty(strings.Split(audience, " "))

		// Validate audiences using the configured strategy
		err := c.Config.GetAudienceStrategy(ctx)(subjectTokenInfo.Audiences, requestedAudiences)
		if err != nil {
			return errorsx.WithStack(fosite.ErrInvalidTarget.WithHint("The requested audience is not allowed.").WithWrap(err))
		}
	} else {
		// If no audience is specified, use the audience from the subject token
		requestedAudiences = subjectTokenInfo.Audiences
	}

	// Store the token exchange request for later use in PopulateTokenEndpointResponse
	exchangeRequest := &TokenExchangeRequest{
		SubjectToken:       subjectToken,
		SubjectTokenType:   subjectTokenType,
		SubjectTokenInfo:   subjectTokenInfo,
		ActorToken:         actorToken,
		ActorTokenType:     actorTokenType,
		ActorTokenInfo:     actorTokenInfo,
		RequestedTokenType: requestedTokenType,
		Audience:           requestedAudiences,
		Scopes:             requestedScopes,
		Resource:           resource,
	}

	// Store the exchange request in the session
	session := &TokenExchangeSession{
		ExchangeRequest: exchangeRequest,
		Subject:         subjectTokenInfo.Subject,
		Extra:           map[string]interface{}{},
	}

	request.SetSession(session)

	return nil
}

// PopulateTokenEndpointResponse creates the token exchange response
func (c *Handler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	session, ok := request.GetSession().(*TokenExchangeSession)
	if !ok {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Invalid session type for token exchange."))
	}

	exchangeRequest := session.ExchangeRequest

	// Determine the token type to issue
	tokenType := TokenTypeAccessToken
	if exchangeRequest.RequestedTokenType != "" {
		tokenType = exchangeRequest.RequestedTokenType
	}

	// Create a new access token
	lifespan := c.Config.GetAccessTokenLifespan(ctx)

	// Generate new token
	token, signature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, request)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// Store the new token
	if err := c.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, request); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// Set the response
	response.SetAccessToken(token)
	response.SetTokenType("Bearer")
	response.SetExpiresIn(lifespan)
	response.SetScopes(exchangeRequest.Scopes)

	// Set the issued token type
	response.SetExtra("issued_token_type", tokenType)

	// If actor token was provided, include actor information
	if exchangeRequest.ActorTokenInfo != nil {
		response.SetExtra("actor", map[string]interface{}{
			"sub": exchangeRequest.ActorTokenInfo.Subject,
		})
	}

	return nil
}

// isValidTokenType checks if the token type is supported
func (c *Handler) isValidTokenType(ctx context.Context, tokenType string) bool {
	supportedTypes := c.Config.GetTokenExchangeTokenTypes(ctx)
	for _, supportedType := range supportedTypes {
		if supportedType == tokenType {
			return true
		}
	}
	return false
}
