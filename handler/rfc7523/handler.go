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

package rfc7523

import (
	"context"
	"time"

	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/i18n"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

const grantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

type Handler struct {
	Storage                  RFC7523KeyStorage
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
	// JWTMaxDuration sets the maximum time after token issued date (if present), during which the token is
	// considered valid. If "iat" claim is not present, then current time will be used as issued date.
	JWTMaxDuration time.Duration

	*oauth2.HandleHelper
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.1.3 (everything) and
// https://tools.ietf.org/html/rfc7523#section-2.1 (everything)
func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if err := c.CheckRequest(request); err != nil {
		return err
	}

	assertion := request.GetRequestForm().Get("assertion")
	if assertion == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHintID(i18n.ErrHintMissingClientAssertionDuplicate, grantTypeJWTBearer))
	}

	token, err := jwt.ParseSigned(assertion)
	if err != nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintID(i18n.ErrHintClientAssertionParsingError).
			WithWrap(err).WithDebug(err.Error()),
		)
	}

	// Check fo required claims in token, so we can later find public key based on them.
	if err := c.validateTokenPreRequisites(token); err != nil {
		return err
	}

	key, err := c.findPublicKeyForToken(ctx, token)
	if err != nil {
		return err
	}

	claims := jwt.Claims{}
	if err := token.Claims(key, &claims); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintID(i18n.ErrHintClientAssertionVerifyErrorDuplicate).
			WithWrap(err).WithDebug(err.Error()),
		)
	}

	if err := c.validateTokenClaims(ctx, claims, key); err != nil {
		return err
	}

	scopes, err := c.Storage.GetPublicKeyScopes(ctx, claims.Issuer, claims.Subject, key.KeyID)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	for _, scope := range request.GetRequestedScopes() {
		if !c.ScopeStrategy(scopes, scope) {
			return errorsx.WithStack(fosite.ErrInvalidScope.WithHintID(i18n.ErrHintClientAssertionScopeNotAllowed, claims.Issuer, claims.Subject, scope))
		}
	}

	if claims.ID != "" {
		if err := c.Storage.MarkJWTUsedForTime(ctx, claims.ID, claims.Expiry.Time()); err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	for _, scope := range request.GetRequestedScopes() {
		request.GrantScope(scope)
	}

	for _, audience := range claims.Audience {
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

func (c *Handler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	if err := c.CheckRequest(request); err != nil {
		return err
	}

	return c.IssueAccessToken(ctx, request, response)
}

func (c *Handler) CanSkipClientAuth(requester fosite.AccessRequester) bool {
	return c.SkipClientAuth
}

func (c *Handler) CanHandleTokenEndpointRequest(requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "authorization_code"
	return requester.GetGrantTypes().ExactOne(grantTypeJWTBearer)
}

func (c *Handler) CheckRequest(request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	// Client Authentication is optional:
	//
	// Authentication of the client is optional, as described in
	//   Section 3.2.1 of OAuth 2.0 [RFC6749] and consequently, the
	//   "client_id" is only needed when a form of client authentication that
	//   relies on the parameter is used.

	// if client is authenticated, check grant types
	if !c.CanSkipClientAuth(request) && !request.GetClient().GetGrantTypes().Has(grantTypeJWTBearer) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHintID(i18n.ErrHintAuthorizationGrantNotSupported, grantTypeJWTBearer))
	}

	return nil
}

func (c *Handler) validateTokenPreRequisites(token *jwt.JSONWebToken) error {
	unverifiedClaims := jwt.Claims{}
	if err := token.UnsafeClaimsWithoutVerification(&unverifiedClaims); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintID(i18n.ErrHintMissingClientAssertionClaims).
			WithWrap(err).WithDebug(err.Error()),
		)
	}
	if unverifiedClaims.Issuer == "" {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintID(i18n.ErrHintMissingClientAssertionIssuer),
		)
	}
	if unverifiedClaims.Subject == "" {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintID(i18n.ErrHintMissingClientAssertionSubjectDuplicate),
		)
	}

	return nil
}

func (c *Handler) findPublicKeyForToken(ctx context.Context, token *jwt.JSONWebToken) (*jose.JSONWebKey, error) {
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

	keyNotFoundErr := fosite.ErrInvalidGrant.WithHintID(
		i18n.ErrHintClientAssertionNoPublicJWKConfigured,
		unverifiedClaims.Issuer,
		unverifiedClaims.Subject,
	)
	if keyID != "" {
		key, err := c.Storage.GetPublicKey(ctx, unverifiedClaims.Issuer, unverifiedClaims.Subject, keyID)
		if err != nil {
			return nil, errorsx.WithStack(keyNotFoundErr.WithWrap(err).WithDebug(err.Error()))
		}
		return key, nil
	}

	keys, err := c.Storage.GetPublicKeys(ctx, unverifiedClaims.Issuer, unverifiedClaims.Subject)
	if err != nil {
		return nil, errorsx.WithStack(keyNotFoundErr.WithWrap(err).WithDebug(err.Error()))
	}

	claims := jwt.Claims{}
	for _, key := range keys.Keys {
		err := token.Claims(key, &claims)
		if err == nil {
			return &key, nil
		}
	}

	return nil, errorsx.WithStack(keyNotFoundErr)
}

func (c *Handler) validateTokenClaims(ctx context.Context, claims jwt.Claims, key *jose.JSONWebKey) error {
	if len(claims.Audience) == 0 {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintID(i18n.ErrHintInvalidClientAssertionAudienceDuplicate),
		)
	}

	if !claims.Audience.Contains(c.TokenURL) {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintID(
				i18n.ErrHintInvalidClientAssertionAudience,
				c.TokenURL,
			),
		)
	}

	if claims.Expiry == nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintID(i18n.ErrHintMissingClientAssertionExpiry),
		)
	}

	if claims.Expiry.Time().Before(time.Now()) {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintID(i18n.ErrHintClientAssertionExpired),
		)
	}

	if claims.NotBefore != nil && !claims.NotBefore.Time().Before(time.Now()) {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintID(
				i18n.ErrHintClientAssertionNotValidYet,
				claims.NotBefore.Time().Format(time.RFC3339),
			),
		)
	}

	if !c.JWTIssuedDateOptional && claims.IssuedAt == nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintID(i18n.ErrHintMissingClientAssertionIssuedAt),
		)
	}

	var issuedDate time.Time
	if claims.IssuedAt != nil {
		issuedDate = claims.IssuedAt.Time()
	} else {
		issuedDate = time.Now()
	}
	if claims.Expiry.Time().Sub(issuedDate) > c.JWTMaxDuration {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintID(
				i18n.ErrHintClientAssertionValidityTooLong,
				claims.Expiry.Time().Format(time.RFC3339),
				issuedDate.Format(time.RFC3339),
			),
		)
	}

	if !c.JWTIDOptional && claims.ID == "" {
		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHintID(i18n.ErrHintMissingClientAssertionJTIDuplicate),
		)
	}

	if claims.ID != "" {
		used, err := c.Storage.IsJWTUsed(ctx, claims.ID)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
		if used {
			return errorsx.WithStack(fosite.ErrJTIKnown)
		}
	}

	return nil
}

type extendedSession interface {
	Session
	fosite.Session
}

func (c *Handler) getSessionFromRequest(requester fosite.AccessRequester) (extendedSession, error) {
	session := requester.GetSession()
	if jwtSession, ok := session.(extendedSession); !ok {
		return nil, errorsx.WithStack(
			fosite.ErrServerError.WithHintID(i18n.ErrHintInvalidClientAssertionSessionType, session),
		)
	} else {
		return jwtSession, nil
	}
}
