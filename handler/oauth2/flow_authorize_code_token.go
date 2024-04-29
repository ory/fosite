// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"github.com/pkg/errors"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
)

type AuthorizeCodeHandler struct {
	AuthorizeCodeStrategy AuthorizeCodeStrategy
}

func (c AuthorizeCodeHandler) Code(ctx context.Context, requester fosite.AccessRequester) (string, string, error) {
	code := requester.GetRequestForm().Get("code")
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	return code, signature, nil
}

func (c AuthorizeCodeHandler) ValidateCode(ctx context.Context, requester fosite.Requester, code string) error {
	return nil
}

func (c AuthorizeCodeHandler) ValidateCodeSession(ctx context.Context, requester fosite.Requester, code string) error {
	return c.AuthorizeCodeStrategy.ValidateAuthorizeCode(ctx, requester, code)
}

type AuthorizeExplicitGrantSessionHandler struct {
	AuthorizeCodeStorage AuthorizeCodeStorage
}

func (s AuthorizeExplicitGrantSessionHandler) Session(ctx context.Context, requester fosite.AccessRequester, codeSignature string) (fosite.Requester, error) {
	req, err := s.AuthorizeCodeStorage.GetAuthorizeCodeSession(ctx, codeSignature, requester.GetSession())

	if err != nil && errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) {
		if req != nil {
			return req, err
		}

		return req, fosite.ErrServerError.
			WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
			WithDebug("\"GetAuthorizeCodeSession\" must return a value for \"fosite.Requester\" when returning \"ErrInvalidatedAuthorizeCode\".")
	}

	if err != nil && errors.Is(err, fosite.ErrNotFound) {
		return nil, errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
	}

	if err != nil {
		return nil, errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return req, err
}

func (s AuthorizeExplicitGrantSessionHandler) InvalidateSession(ctx context.Context, codeSignature string) error {
	return s.AuthorizeCodeStorage.InvalidateAuthorizeCodeSession(ctx, codeSignature)
}

type AuthorizeExplicitGrantAccessRequestValidator struct{}

func (v AuthorizeExplicitGrantAccessRequestValidator) CanHandleRequest(requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne("authorization_code")
}

func (v AuthorizeExplicitGrantAccessRequestValidator) ValidateGrantTypes(requester fosite.AccessRequester) error {
	if !requester.GetClient().GetGrantTypes().Has("authorization_code") {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"authorization_code\"."))
	}

	return nil
}

func (v AuthorizeExplicitGrantAccessRequestValidator) GetGrantType(requester fosite.AccessRequester) fosite.GrantType {
	return fosite.GrantTypeAuthorizationCode
}

func (v AuthorizeExplicitGrantAccessRequestValidator) ValidateRedirectURI(accessRequester fosite.AccessRequester, authorizeRequester fosite.Requester) error {
	forcedRedirectURI := authorizeRequester.GetRequestForm().Get("redirect_uri")
	requestedRedirectURI := accessRequester.GetRequestForm().Get("redirect_uri")
	if forcedRedirectURI != "" && forcedRedirectURI != requestedRedirectURI {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The \"redirect_uri\" from this request does not match the one from the authorize request."))
	}

	return nil
}

type AuthorizeExplicitTokenEndpointHandler struct {
	GenericCodeTokenEndpointHandler
}

var (
	_ AccessRequestValidator      = (*AuthorizeExplicitGrantAccessRequestValidator)(nil)
	_ CodeHandler                 = (*AuthorizeCodeHandler)(nil)
	_ SessionHandler              = (*AuthorizeExplicitGrantSessionHandler)(nil)
	_ fosite.TokenEndpointHandler = (*AuthorizeExplicitTokenEndpointHandler)(nil)
)
