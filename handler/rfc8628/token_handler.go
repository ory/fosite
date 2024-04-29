// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"

	"github.com/pkg/errors"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

type DeviceCodeHandler struct {
	DeviceRateLimitStrategy DeviceRateLimitStrategy
	DeviceCodeStrategy      DeviceCodeStrategy
}

func (c DeviceCodeHandler) Code(ctx context.Context, requester fosite.AccessRequester) (code string, signature string, err error) {
	code = requester.GetRequestForm().Get("device_code")

	signature, err = c.DeviceCodeStrategy.DeviceCodeSignature(ctx, code)
	if err != nil {
		return "", "", errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return
}

func (c DeviceCodeHandler) ValidateCode(ctx context.Context, requester fosite.Requester, code string) error {
	shouldRateLimit, err := c.DeviceRateLimitStrategy.ShouldRateLimit(ctx, code)
	if err != nil {
		return err
	}
	if shouldRateLimit {
		return errorsx.WithStack(fosite.ErrPollingRateLimited)
	}
	return nil
}

func (c DeviceCodeHandler) ValidateCodeSession(ctx context.Context, requester fosite.Requester, code string) error {
	return c.DeviceCodeStrategy.ValidateDeviceCode(ctx, requester, code)
}

type DeviceSessionHandler struct {
	DeviceCodeStorage DeviceCodeStorage
}

func (s DeviceSessionHandler) Session(ctx context.Context, requester fosite.AccessRequester, codeSignature string) (fosite.Requester, error) {
	req, err := s.DeviceCodeStorage.GetDeviceCodeSession(ctx, codeSignature, requester.GetSession())

	if err != nil && errors.Is(err, fosite.ErrInvalidatedDeviceCode) {
		if req != nil {
			return req, err
		}

		return req, fosite.ErrServerError.
			WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
			WithDebug("\"GetDeviceCodeSession\" must return a value for \"fosite.Requester\" when returning \"ErrInvalidatedDeviceCode\".")
	}

	if err != nil && errors.Is(err, fosite.ErrAuthorizationPending) {
		return nil, err
	}

	if err != nil && errors.Is(err, fosite.ErrNotFound) {
		return nil, errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
	}

	if err != nil {
		return nil, errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	session, ok := req.GetSession().(DeviceFlowSession)
	if !ok {
		return nil, fosite.ErrServerError.WithHint("Wrong authorization request session.")
	}

	if !session.GetBrowserFlowCompleted() {
		return nil, fosite.ErrAuthorizationPending
	}

	return req, err
}

func (s DeviceSessionHandler) InvalidateSession(ctx context.Context, codeSignature string) error {
	return s.DeviceCodeStorage.InvalidateDeviceCodeSession(ctx, codeSignature)
}

type DeviceAccessRequestValidator struct{}

func (v DeviceAccessRequestValidator) CanHandleRequest(requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeDeviceCode))
}

func (v DeviceAccessRequestValidator) ValidateGrantTypes(requester fosite.AccessRequester) error {
	if !requester.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeDeviceCode)) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:device_code\"."))
	}

	return nil
}

func (v DeviceAccessRequestValidator) ValidateRedirectURI(accessRequester fosite.AccessRequester, authorizeRequester fosite.Requester) error {
	return nil
}

func (v DeviceAccessRequestValidator) GetGrantType(requester fosite.AccessRequester) fosite.GrantType {
	return fosite.GrantTypeDeviceCode
}

type DeviceCodeTokenEndpointHandler struct {
	oauth2.GenericCodeTokenEndpointHandler
}

var (
	_ oauth2.AccessRequestValidator = (*DeviceAccessRequestValidator)(nil)
	_ oauth2.CodeHandler            = (*DeviceCodeHandler)(nil)
	_ oauth2.SessionHandler         = (*DeviceSessionHandler)(nil)
	_ fosite.TokenEndpointHandler   = (*DeviceCodeTokenEndpointHandler)(nil)
)
