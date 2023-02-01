// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
)

// AuthorizeExplicitGrantTokenHandler is a response handler for the Authorize Code grant using the explicit grant type
// as defined in https://tools.ietf.org/html/rfc6749#section-4.1
type AuthorizeExplicitGrantTokenHandler struct {
	AuthorizeCodeStrategy AuthorizeCodeStrategy
	AuthorizeCodeStorage  AuthorizeCodeStorage
}

var _ CodeTokenEndpointHandler = (*AuthorizeExplicitGrantTokenHandler)(nil)

func (c *AuthorizeExplicitGrantTokenHandler) ValidateGrantTypes(ctx context.Context, requester fosite.AccessRequester) error {
	if !requester.GetClient().GetGrantTypes().Has("authorization_code") {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"authorization_code\"."))
	}

	return nil
}

func (c *AuthorizeExplicitGrantTokenHandler) ValidateCode(ctx context.Context, request fosite.AccessRequester, code string) error {
	return c.AuthorizeCodeStrategy.ValidateAuthorizeCode(ctx, request, code)
}

func (c *AuthorizeExplicitGrantTokenHandler) GetCodeAndSession(ctx context.Context, requester fosite.AccessRequester) (string, string, fosite.Requester, error) {
	code := requester.GetRequestForm().Get("code")
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	req, err := c.AuthorizeCodeStorage.GetAuthorizeCodeSession(ctx, signature, requester.GetSession())
	return code, signature, req, err
}

func (c *AuthorizeExplicitGrantTokenHandler) InvalidateSession(ctx context.Context, signature string) error {
	return c.AuthorizeCodeStorage.InvalidateAuthorizeCodeSession(ctx, signature)
}

// implement TokenEndpointHandler
func (c *AuthorizeExplicitGrantTokenHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

func (c *AuthorizeExplicitGrantTokenHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne("authorization_code")
}
