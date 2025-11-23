// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
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
	Config interface {
		fosite.AccessTokenLifespanProvider
		fosite.RefreshTokenLifespanProvider
		fosite.ScopeStrategyProvider
		fosite.AudienceStrategyProvider
		fosite.TokenExchangeEnabledProvider
		fosite.TokenExchangeTokenTypesProvider
	}

	AccessTokenStorage   oauth2.AccessTokenStorage
	RefreshTokenStorage  oauth2.RefreshTokenStorage
	AccessTokenStrategy  oauth2.AccessTokenStrategy
	RefreshTokenStrategy oauth2.RefreshTokenStrategy

	*oauth2.HandleHelper
}

var _ fosite.TokenEndpointHandler = (*Handler)(nil)

// Implement ValidateSubjectToken
func (c *Handler) ValidateSubjectToken(ctx context.Context, token string, tokenType string, client fosite.Client) (*TokenInfo, error) {
	log.Printf("Validating subject token: %s type: %s", token, tokenType)

	var req fosite.Requester
	var session fosite.Session
	var err error

	switch tokenType {
	case TokenTypeAccessToken:
		log.Printf("Validating accesstoken: %s", token)

		signature := c.AccessTokenStrategy.AccessTokenSignature(ctx, token)
		log.Printf("Validating accesstoken, signature: %s", signature)

		req, err = c.AccessTokenStorage.GetAccessTokenSession(ctx, signature, nil)
		if err != nil {
			log.Printf("Failed to retrieve access token session: %v", err)
			return nil, fmt.Errorf("invalid access token: %w", err)
		}

		session = req.GetSession()
		if session.GetExpiresAt(fosite.AccessToken).Before(time.Now().UTC()) {
			return nil, fmt.Errorf("access token is expired")
		}
	case TokenTypeRefreshToken:
		log.Printf("Validating refreshtoken: %s", token)

		signature := c.RefreshTokenStrategy.RefreshTokenSignature(ctx, token)
		log.Printf("Validating refreshtoken, signature: %s", signature)

		req, err = c.RefreshTokenStorage.GetRefreshTokenSession(ctx, signature, nil)
		if err != nil {
			log.Printf("Failed to retrieve refresh token session: %v", err)
			return nil, fmt.Errorf("invalid refresh token: %w", err)
		}
		session = req.GetSession()
		if session.GetExpiresAt(fosite.RefreshToken).Before(time.Now().UTC()) {
			return nil, fmt.Errorf("refresh token is expired")
		}

	default:
		log.Printf("Tokentype: %s not (yet) implemented", tokenType)
		return nil, fmt.Errorf("unknown token type: %s", tokenType)
	}

	// Extract token information
	tokenInfo := &TokenInfo{
		Subject:   session.GetSubject(),
		Scopes:    req.GetGrantedScopes(),
		Audiences: req.GetGrantedAudience(),
		TokenType: tokenType,
		Extra:     make(map[string]interface{}),
	}

	log.Printf("✅ Subject token validated: %s, tokeninfo: %+v", token, tokenInfo)

	return tokenInfo, nil

}

// ValidateActorToken (can delegate to ValidateSubjectToken)
func (c *Handler) ValidateActorToken(ctx context.Context, token string, tokenType string, client fosite.Client) (*TokenInfo, error) {
	log.Printf("Validating actor token: %s type: %s", token, tokenType)
	return c.ValidateSubjectToken(ctx, token, tokenType, client)
}

// CanHandleTokenEndpointRequest returns true if the grant type is token exchange
func (c *Handler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	log.Printf("🔗 Checking if request can be handled by Token Exchange Handler")
	return requester.GetGrantTypes().ExactOne(GrantTypeTokenExchange)
}

// CanSkipClientAuth returns false as client authentication is required for token exchange
func (c *Handler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	log.Printf("🔗 Token Exchange requires client authentication")
	return false
}

// HandleTokenEndpointRequest handles the token exchange request
func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	log.Printf("🔗 Token exchange request received from client: %s", request.GetClient().GetID())

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
	subjectTokenInfo, err := c.ValidateSubjectToken(ctx, subjectToken, subjectTokenType, client)
	if err != nil {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("The subject_token is invalid.").WithWrap(err))
	}

	// Validate the actor token if provided
	var actorTokenInfo *TokenInfo
	if actorToken != "" {
		actorTokenInfo, err = c.ValidateActorToken(ctx, actorToken, actorTokenType, client)
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
	request.SetSession(&TokenExchangeSession{
		ExchangeRequest: exchangeRequest,
		Subject:         subjectTokenInfo.Subject,
		Extra:           map[string]interface{}{},
	})

	return nil
}

// PopulateTokenEndpointResponse creates the token exchange response
func (c *Handler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	log.Printf("🔗 Populating token exchange response")

	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	session, ok := request.GetSession().(*TokenExchangeSession)
	if !ok {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Invalid session type for token exchange."))
	}

	exchangeRequest := session.ExchangeRequest

	log.Printf("🔗 Populating token exchange response for client: %s, details: %v", request.GetClient().GetID(), exchangeRequest)

	// If 'openid' scope is present, replace session with openid.DefaultSession
	if exchangeRequest.Scopes.Has("openid") {
		openidSession := &openid.DefaultSession{
			Subject: session.Subject,
		}

		openidSession.Claims = &jwt.IDTokenClaims{
			Subject: session.Subject,
			Extra:   make(map[string]interface{}),
		}

		request.SetSession(openidSession)
	}

	// Determine the token type to issue
	tokenType := TokenTypeAccessToken
	if exchangeRequest.RequestedTokenType != "" {
		tokenType = exchangeRequest.RequestedTokenType
	}

	// Grant requested scopes and audiences to the request before token generation
	for _, scope := range exchangeRequest.Scopes {
		request.GrantScope(scope)
	}
	for _, aud := range exchangeRequest.Audience {
		request.GrantAudience(aud)
	}

	lifespan := c.Config.GetAccessTokenLifespan(ctx)

	// Set expiration on the session
	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(lifespan))

	// Generate new token using HandleHelper
	_, err := c.IssueAccessToken(ctx, lifespan, request, response)
	if err != nil {
		return err
	}

	// Set the issued token type
	response.SetExtra("issued_token_type", tokenType)

	if tokenType == TokenTypeRefreshToken {
		// Generate refresh token
		refresh_token, refresh_token_signature, err := c.RefreshTokenStrategy.GenerateRefreshToken(ctx, request)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}

		// Set expiration for refresh token
		request.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(c.Config.GetRefreshTokenLifespan(ctx)))

		// Store the new refresh token
		if err := c.RefreshTokenStorage.CreateRefreshTokenSession(ctx, refresh_token_signature, refresh_token, request); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}

		response.SetExtra("refresh_token", refresh_token)
	}

	// If actor token was provided, include actor information
	if exchangeRequest.ActorTokenInfo != nil {
		response.SetExtra("actor", map[string]interface{}{
			"sub": exchangeRequest.ActorTokenInfo.Subject,
		})
	}

	//	c.Interface.StoreTokenExchange(ctx, exchangeRequest, exchangeResponse)
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
