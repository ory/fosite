// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/ory/x/errorsx"
)

type CustomJWTTypeHandler struct {
	Config      fosite.RFC8693ConfigProvider
	JWTStrategy jwt.Signer
	Storage
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *CustomJWTTypeHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	session, _ := request.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	form := request.GetRequestForm()
	tokenTypes := c.Config.GetTokenTypes(ctx)
	actorTokenType := tokenTypes[form.Get("actor_token_type")]
	subjectTokenType := tokenTypes[form.Get("subject_token_type")]
	if actorTokenType != nil && actorTokenType.GetType(ctx) == JWTTokenType {
		token := form.Get("actor_token")
		if unpacked, err := c.validate(ctx, request, actorTokenType, token); err != nil {
			return err
		} else {
			session.SetActorToken(unpacked)
		}
	}

	if subjectTokenType != nil && subjectTokenType.GetType(ctx) == JWTTokenType {
		token := form.Get("subject_token")
		if unpacked, err := c.validate(ctx, request, subjectTokenType, token); err != nil {
			return err
		} else {
			session.SetSubjectToken(unpacked)
			// Get the subject and populate session
			if subject, err := c.Storage.GetSubjectForTokenExchange(ctx, request, unpacked); err != nil {
				return err
			} else {
				session.SetSubject(subject)
			}
		}
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *CustomJWTTypeHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, responder fosite.AccessResponder) error {

	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	session, _ := request.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	form := request.GetRequestForm()
	requestedTokenType := form.Get("requested_token_type")
	if requestedTokenType == "" {
		requestedTokenType = c.Config.GetDefaultRequestedTokenType(ctx)
	}

	tokenTypes := c.Config.GetTokenTypes(ctx)
	tokenType := tokenTypes[requestedTokenType]
	if tokenType == nil || tokenType.GetType(ctx) != JWTTokenType {
		return nil
	}

	if err := c.issue(ctx, request, tokenType, responder); err != nil {
		return err
	}

	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *CustomJWTTypeHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *CustomJWTTypeHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "password".
	return requester.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:token-exchange")
}

func (c *CustomJWTTypeHandler) validate(ctx context.Context, request fosite.AccessRequester, tokenType fosite.RFC8693TokenType, token string) (map[string]interface{}, error) {

	jwtType, _ := tokenType.(*JWTType)
	if jwtType == nil {
		return nil, errorsx.WithStack(
			fosite.ErrServerError.WithDebugf(
				"Token type '%s' is supposed to be of type JWT but is not castable to 'JWTType'", tokenType.GetName(ctx)))
	}

	// Parse the token
	ftoken, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, jwtType.ValidateFunc)
	if err != nil {
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Unable to parse the JSON web token").WithWrap(err).WithDebug(err.Error()))
	}

	window := jwtType.JWTLifetimeToleranceWindow
	if window == 0 {
		window = 1 * time.Hour
	}
	claims := ftoken.Claims

	if issued, exists := claims["iat"]; exists {
		if time.Unix(toInt64(issued), 0).Add(window).Before(time.Now()) {
			return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Claim 'iat' from token is too far in the past."))
		}
	}

	if _, exists := claims["exp"]; !exists { // Validate 'exp' is mandatory
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Claim 'exp' from token is missing."))
	}
	expiry := toInt64(claims["exp"])
	if time.Now().Add(window).Before(time.Unix(expiry, 0)) {
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Claim 'exp' from token is too far in the future."))
	}

	if !claims.VerifyIssuer(jwtType.Issuer, true) {
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("Claim 'iss' from token must match the '%s'.", jwtType.Issuer))
	}

	// Validate the JTI is unique if required
	if jwtType.ValidateJTI {
		jti, _ := claims["jti"].(string)
		if jti == "" {
			return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Claim 'jti' from token is missing."))
		}

		if c.Storage.SetTokenExchangeCustomJWT(ctx, jti, time.Unix(expiry, 0)) != nil {
			return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Claim 'jti' from the token must be used only once."))
		}
	}

	return map[string]interface{}(claims), nil
}

func (c *CustomJWTTypeHandler) issue(ctx context.Context, request fosite.AccessRequester, tokenType fosite.RFC8693TokenType, response fosite.AccessResponder) error {
	jwtType, _ := tokenType.(*JWTType)
	if jwtType == nil {
		return errorsx.WithStack(
			fosite.ErrServerError.WithDebugf(
				"Token type '%s' is supposed to be of type JWT but is not castable to 'JWTType'", tokenType.GetName(ctx)))
	}

	sess, ok := request.GetSession().(openid.Session)
	if !ok {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to generate JWT because session must be of type fosite/handler/openid.Session."))
	}

	claims := sess.IDTokenClaims()
	if claims.Subject == "" {
		claims.Subject = request.GetClient().GetID()
	}

	if claims.ExpiresAt.IsZero() {
		claims.ExpiresAt = time.Now().UTC().Add(jwtType.Expiry)
	}

	if claims.Issuer == "" {
		claims.Issuer = jwtType.Issuer
	}

	if len(request.GetRequestedAudience()) > 0 {
		claims.Audience = append(claims.Audience, request.GetRequestedAudience()...)
	}

	if len(claims.Audience) == 0 {
		aud := jwtType.JWTIssueConfig.Audience
		if len(aud) == 0 {
			aud = append(aud, request.GetClient().GetID())
		}

		claims.Audience = append(claims.Audience, aud...)
	}

	if claims.JTI == "" {
		claims.JTI = uuid.New().String()
	}

	claims.IssuedAt = time.Now().UTC()

	token, _, err := c.JWTStrategy.Generate(ctx, claims.ToMapClaims(), sess.IDTokenHeaders())
	if err != nil {
		return err
	}

	response.SetAccessToken(token)
	response.SetTokenType("N_A")
	response.SetExpiresIn(time.Duration(claims.ExpiresAt.UnixNano() - time.Now().UTC().UnixNano()))
	return nil
}

// type conversion according to jwt.MapClaims.toInt64 - ignore error
func toInt64(claim interface{}) int64 {
	switch t := claim.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case json.Number:
		v, err := t.Int64()
		if err == nil {
			return v
		}
		vf, err := t.Float64()
		if err != nil {
			return 0
		}
		return int64(vf)
	}
	return 0
}
