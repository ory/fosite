// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc9396

import (
	"context"
	"encoding/json"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

var _ fosite.AuthorizeEndpointValidationHandler = (*AuthorizeHandler)(nil)
var _ fosite.DeviceAuthorizeEndpointValidationHandler = (*AuthorizeHandler)(nil)
var _ fosite.AuthorizeEndpointHandler = (*AuthorizeHandler)(nil)

// AuthorizeHandler validates the authorization_details provided in the request and updates
// the responder with the appropriate granted authorization_details.
type AuthorizeHandler struct {
	Config fosite.RFC9396ConfigProvider
}

// ValidateAuthorizeEndpointRequest validates and enriches an authorize endpoint request. This mirrors TokenEndpointHandler's
// HandleTokenEndpointRequest, which is used for the same purpose.
func (h *AuthorizeHandler) ValidateAuthorizeEndpointRequest(ctx context.Context, requester fosite.AuthorizeRequester) error {

	// check requester type
	req, ok := requester.(fosite.RFC9396Requester)
	if !ok {
		return nil
	}

	return validateAndEnrichRequester(ctx, requester.GetClient(), req, h.Config, requester.GetRequestForm().Get("authorization_details"))
}

// ValidateDeviceAuthorizeEndpointRequest validates and enriches an authorize endpoint request. This mirrors TokenEndpointHandler's
// HandleTokenEndpointRequest, which is used for the same purpose.
func (h *AuthorizeHandler) ValidateDeviceAuthorizeEndpointRequest(ctx context.Context, requester fosite.DeviceAuthorizeRequester) error {
	// check requester type
	req, ok := requester.(fosite.RFC9396Requester)
	if !ok {
		return nil
	}

	return validateAndEnrichRequester(ctx, requester.GetClient(), req, h.Config, requester.GetRequestForm().Get("authorization_details"))
}

func (h *AuthorizeHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	// check if the token is issued in the authorize endpoint response
	if !ar.GetResponseTypes().Has("token") {
		return nil
	}

	req, ok := ar.(fosite.RFC9396Requester)
	if !ok {
		return nil
	}

	// check if the client is configured correctly. This isn't actually needed because other handlers would cover this
	// but this has been added for completeness.
	if !ar.GetClient().GetGrantTypes().Has("implicit") {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'implicit'."))
	}

	// marshal the authorization details that are granted
	granted := req.GetGrantedAuthorizationDetails()
	if len(granted) > 0 {
		b, err := json.Marshal(granted)
		if err != nil {
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHint("Invalid authorization details value").WithWrap(err))
		}

		resp.AddParameter("authorization_details", string(b))
	}

	return nil
}

func validateAndEnrichRequester(ctx context.Context, c fosite.Client, req fosite.RFC9396Requester, config fosite.RFC9396ConfigProvider, param string) error {
	if len(param) == 0 {
		return nil
	}

	// deserialize the authorization details
	types := []*fosite.RFC9396AuthorizationDetailsType{}
	if err := json.Unmarshal([]byte(param), &types); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHint("Invalid authorization_details value.").WithWrap(err))
	}

	typesSupported := fosite.Arguments(config.GetAuthorizationDetailTypesSupported(ctx))
	strategy := config.GetAuthorizationDetailsStrategy(ctx)
	ignoreUnknownAuthorizationDetailsType := config.GetIgnoreUnknownAuthorizationDetailsType(ctx)
	client, _ := c.(fosite.RFC9396Client)
	for _, ad := range types {
		if len(ad.Type) == 0 {
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHint("Missing 'type' in the authorization details object."))
		}

		if !typesSupported.Has(ad.Type) {
			if ignoreUnknownAuthorizationDetailsType {
				continue
			}

			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHintf("Unknown authorization detail type %s", ad.Type))
		}

		if client != nil && strategy != nil && !strategy(client.GetAuthorizationDetailTypes(), ad.Type) {
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHintf("The OAuth 2.0 Client is not allowed to request authorization details of type '%s'.", ad.Type))
		}

		ad.DecorateWithTypeHandler(ctx, config)
		if err := ad.Validate(); err != nil {
			return err
		}

		req.AppendRequestedAuthorizationDetail(ad)
	}

	return nil
}
