/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package oauth2

import (
	"context"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const grantTypeJwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

type AuthorizeJwtGrantHandler struct {
	AuthorizeJwtGrantStorage AuthorizeJwtGrantStorage
	ScopeStrategy            fosite.ScopeStrategy
	AudienceMatchingStrategy fosite.AudienceMatchingStrategy

	// TokenURL is the the URL of the Authorization Server's Token Endpoint.
	TokenURL string
	// SkipClientAuth indicates, if client authentication can be skipped.
	SkipClientAuth bool
	// JWTIDOptional indicates, if jti (JWT ID) claim required or not.
	JWTIDOptional bool
	// JWTIssuedDateOptional indicates, if "iat" (issued at) claim required or not.
	JWTIssuedDateOptional bool
	// JWTMaxDuration sets the maximum time after token issued date, during which the token is considered valid.
	JWTMaxDuration time.Duration

	*HandleHelper
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.1.3 (everything) and
// https://tools.ietf.org/html/rfc7523#section-2.1 (everything)
func (c *AuthorizeJwtGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	// if client is authenticated, check grant types
	if !c.CanSkipClientAuth(request) && !request.GetClient().GetGrantTypes().Has(grantTypeJwtBearer) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHintf("The OAuth 2.0 Client is not allowed to use authorization grant \"%s\".", grantTypeJwtBearer))
	}

	assertion := request.GetRequestForm().Get("assertion")
	if assertion == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("The assertion request parameter must be set when using grant_type of '%s'.", grantTypeJwtBearer))
	}

	token, err := jwt.ParseSigned(assertion)
	if err != nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("Unable to parse jwt token passed in \"assertion\" request parameter.").
			WithWrap(err).WithDebug(err.Error()),
		)
	}

	// check fo required claims in token, so we can later find public key based on them
	if err := c.validateTokenPreRequisites(token); err != nil {
		return err
	}

	key, err := c.findPublicKeyForToken(ctx, token)
	if err != nil {
		return err
	}

	if err := c.validateToken(ctx, token, key); err != nil {
		return err
	}

	claims := jwt.Claims{}
	if err := token.Claims(key, &claims); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("Unable to verify the integrity of the 'assertion' value.").
			WithWrap(err).WithDebug(err.Error()),
		)
	}

	if claims.ID != "" {
		if err := c.AuthorizeJwtGrantStorage.MarkJWTUsedForTime(ctx, claims.ID, claims.Expiry.Time()); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	scopes, err := c.AuthorizeJwtGrantStorage.GetPublicKeyScopes(ctx, claims.Issuer, claims.Subject, key.KeyID)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	for _, scope := range request.GetRequestedScopes() {
		if !c.ScopeStrategy(scopes, scope) {
			return errorsx.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
	}

	for _, scope := range request.GetRequestedScopes() {
		request.GrantScope(scope)
	}

	for _, audience := range request.GetRequestedAudience() {
		request.GrantAudience(audience)
	}

	session, err := c.getSessionFromRequest(request)
	if err != nil {
		return err
	}
	session.SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(c.HandleHelper.AccessTokenLifespan).Round(time.Second))
	session.SetSubject(claims.Subject)

	return nil
}

func (c *AuthorizeJwtGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	// if client is authenticated, check grant types
	if !c.CanSkipClientAuth(request) && !request.GetClient().GetGrantTypes().Has(grantTypeJwtBearer) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHintf("The OAuth 2.0 Client is not allowed to use authorization grant \"%s\".", grantTypeJwtBearer))
	}

	return c.IssueAccessToken(ctx, request, response)
}

func (c *AuthorizeJwtGrantHandler) CanSkipClientAuth(requester fosite.AccessRequester) bool {
	return c.SkipClientAuth
}

func (c *AuthorizeJwtGrantHandler) CanHandleTokenEndpointRequest(requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "authorization_code"
	return requester.GetGrantTypes().ExactOne(grantTypeJwtBearer)
}

func (c *AuthorizeJwtGrantHandler) validateTokenPreRequisites(token *jwt.JSONWebToken) error {
	unverifiedClaims := jwt.Claims{}
	if err := token.UnsafeClaimsWithoutVerification(&unverifiedClaims); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("Looks like there are no claims in JWT in \"assertion\" request parameter.").
			WithWrap(err).WithDebug(err.Error()),
		)
	}
	if unverifiedClaims.Issuer == "" {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("The JWT in \"assertion\" request parameter MUST contain an \"iss\" (issuer) claim."),
		)
	}
	if unverifiedClaims.Subject == "" {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("The JWT in \"assertion\" request parameter MUST contain a \"sub\" (subject) claim."),
		)
	}

	return nil
}

func (c *AuthorizeJwtGrantHandler) findPublicKeyForToken(ctx context.Context, token *jwt.JSONWebToken) (*jose.JSONWebKey, error) {
	unverifiedClaims := jwt.Claims{}
	if err := token.UnsafeClaimsWithoutVerification(&unverifiedClaims); err != nil {
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithWrap(err).WithDebug(err.Error()))
	}

	var keyID string
	for _, header := range token.Headers {
		if header.KeyID != "" {
			keyID = header.KeyID
			break
		}
	}

	keyNotFoundMsg := fmt.Sprintf(
		"No public JWK was registered for issuer \"%s\" and subject \"%s\", and public key is required to check signature of JWT in \"assertion\" request parameter.",
		unverifiedClaims.Issuer,
		unverifiedClaims.Subject,
	)
	if keyID != "" {
		key, err := c.AuthorizeJwtGrantStorage.GetPublicKey(ctx, unverifiedClaims.Issuer, unverifiedClaims.Subject, keyID)
		if err != nil {
			return nil, errorsx.WithStack(fosite.ErrInvalidGrant.WithHint(keyNotFoundMsg).WithWrap(err).WithDebug(err.Error()))
		}
		return key, nil
	}

	keys, err := c.AuthorizeJwtGrantStorage.GetPublicKeys(ctx, unverifiedClaims.Issuer, unverifiedClaims.Subject)
	if err != nil {
		return nil, errorsx.WithStack(fosite.ErrInvalidGrant.WithHint(keyNotFoundMsg).WithWrap(err).WithDebug(err.Error()))
	}

	claims := jwt.Claims{}
	for _, key := range keys.Keys {
		err := token.Claims(key, &claims)
		if err == nil {
			return &key, nil
		}
	}

	return nil, errorsx.WithStack(fosite.ErrInvalidGrant.WithHint(keyNotFoundMsg))
}

func (c *AuthorizeJwtGrantHandler) validateToken(ctx context.Context, token *jwt.JSONWebToken, key *jose.JSONWebKey) error {
	claims := jwt.Claims{}
	if err := token.Claims(key, &claims); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("Unable to verify the integrity of the 'assertion' value.").
			WithWrap(err).WithDebug(err.Error()),
		)
	}

	if len(claims.Audience) == 0 {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("The JWT in \"assertion\" request parameter MUST contain an \"aud\" (audience) claim."),
		)
	}

	if !claims.Audience.Contains(c.TokenURL) {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintf(
				"The JWT in \"assertion\" request parameter MUST contain an \"aud\" (audience) claim containing a value \"%s\" that identifies the authorization server as an intended audience.",
				c.TokenURL,
			),
		)
	}

	if claims.Expiry == nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("The JWT in \"assertion\" request parameter MUST contain an \"exp\" (expiration time) claim."),
		)
	}

	if claims.Expiry.Time().Before(time.Now()) {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("The JWT in \"assertion\" request parameter expired."),
		)
	}

	if claims.NotBefore != nil && !claims.NotBefore.Time().Before(time.Now()) {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintf(
				"The JWT in \"assertion\" request parameter contains an \"nbf\" (not before) claim, that identifies the time '%s' before which the token MUST NOT be accepted.",
				claims.NotBefore.Time().Format(time.RFC3339),
			),
		)
	}

	if !c.JWTIssuedDateOptional && claims.IssuedAt == nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("The JWT in \"assertion\" request parameter MUST contain an \"iat\" (issued at) claim."),
		)
	}
	if claims.IssuedAt != nil && time.Now().Sub(claims.IssuedAt.Time()).Nanoseconds() > c.JWTMaxDuration.Nanoseconds() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintf(
				"The JWT in \"assertion\" request parameter contains an \"iat\" (issued at) claim with value \"%s\" that is unreasonably far in the past.",
				claims.IssuedAt.Time().Format(time.RFC3339),
			),
		)
	}

	if !c.JWTIDOptional && claims.ID == "" {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("The JWT in \"assertion\" request parameter MUST contain an \"jti\" (JWT ID) claim."),
		)
	}

	if claims.ID != "" {
		used, err := c.AuthorizeJwtGrantStorage.IsJWTUsed(ctx, claims.ID)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
		if used {
			return errorsx.WithStack(fosite.ErrJTIKnown)
		}
	}

	return nil
}

func (c *AuthorizeJwtGrantHandler) getSessionFromRequest(requester fosite.AccessRequester) (AuthorizeJwtGrantSession, error) {
	session := requester.GetSession()
	if jwtSession, ok := session.(AuthorizeJwtGrantSession); !ok {
		return nil, errorsx.WithStack(
			fosite.ErrServerError.WithHintf("Session must be of type AuthorizeJwtGrantSession but got type: %T", session),
		)
	} else {
		return jwtSession, nil
	}
}
