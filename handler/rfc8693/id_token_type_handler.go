// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8693

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/ory/x/errorsx"
)

type IDTokenTypeHandler struct {
	Config             fosite.Configurator
	JWTStrategy        jwt.Signer
	IssueStrategy      openid.OpenIDConnectTokenStrategy
	ValidationStrategy openid.OpenIDConnectTokenValidationStrategy
	Storage
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.3.2
func (c *IDTokenTypeHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	session, _ := request.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to perform token exchange because the session is not of the right type."))
	}

	form := request.GetRequestForm()
	if form.Get("subject_token_type") != IDTokenType && form.Get("actor_token_type") != IDTokenType {
		return nil
	}

	if form.Get("actor_token_type") == IDTokenType {
		token := form.Get("actor_token")
		if unpacked, err := c.validate(ctx, request, token); err != nil {
			return err
		} else {
			session.SetActorToken(unpacked)
		}
	}

	if form.Get("subject_token_type") == IDTokenType {
		token := form.Get("subject_token")
		if unpacked, err := c.validate(ctx, request, token); err != nil {
			return err
		} else {
			// Get the subject and populate session
			session.SetSubject(unpacked["sub"].(string))
			session.SetSubjectToken(unpacked)
		}
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-4.3.3
func (c *IDTokenTypeHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, responder fosite.AccessResponder) error {
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
		if config, ok := c.Config.(fosite.RFC8693ConfigProvider); ok {
			requestedTokenType = config.GetDefaultRequestedTokenType(ctx)
		}
	}

	if requestedTokenType != IDTokenType {
		return nil
	}

	if err := c.issue(ctx, request, responder); err != nil {
		return err
	}

	return nil
}

// CanSkipClientAuth indicates if client auth can be skipped
func (c *IDTokenTypeHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

// CanHandleTokenEndpointRequest indicates if the token endpoint request can be handled
func (c *IDTokenTypeHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "password".
	return requester.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:token-exchange")
}

func (c *IDTokenTypeHandler) validate(ctx context.Context, request fosite.AccessRequester, token string) (map[string]interface{}, error) {

	claims, err := c.ValidationStrategy.ValidateIDToken(ctx, request, token)
	if err != nil {
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Unable to parse the id_token").WithWrap(err).WithDebug(err.Error()))
	}

	expectedIssuer := ""
	if config, ok := c.Config.(fosite.AccessTokenIssuerProvider); ok {
		expectedIssuer = config.GetAccessTokenIssuer(ctx)
	}

	if !claims.VerifyIssuer(expectedIssuer, true) {
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHintf("Claim 'iss' from token must match the '%s'.", expectedIssuer))
	}

	if _, ok := claims["sub"].(string); !ok {
		return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Claim 'sub' is missing."))
	}

	return map[string]interface{}(claims), nil
}

func (c *IDTokenTypeHandler) issue(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	sess, ok := request.GetSession().(openid.Session)
	if !ok {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug(
			"Failed to generate id token because session must be of type fosite/handler/openid.Session."))
	}

	claims := sess.IDTokenClaims()
	if claims.Subject == "" {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to generate id token because subject is an empty string."))
	}

	token, err := c.IssueStrategy.GenerateIDToken(ctx, c.Config.GetIDTokenLifespan(ctx), request)
	if err != nil {
		return err
	}

	response.SetAccessToken(token)
	response.SetTokenType("N_A")

	return nil
}
