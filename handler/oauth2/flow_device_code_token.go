/*
 * Copyright © 2015-2021 Aeneas Rekkas <aeneas+oss@aeneas.io>
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
 * @author		Luke Stoward
 * @copyright 	2015-2021 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package oauth2

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/ory/x/errorsx"
	"github.com/pkg/errors"
)
 
const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// HandleTokenEndpointRequest implements
// * https://tools.ietf.org/html/rfc8628#section-3.4 (everything)
func (d *DeviceAuthorizationHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !d.CanHandleTokenEndpointRequest(request) {
	return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest))
	}

	if !request.GetClient().GetGrantTypes().Has(deviceCodeGrantType) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \""+ deviceCodeGrantType +"\"."))
	}

	deviceCode := request.GetRequestForm().Get("device_code")
	signature := d.DeviceCodeStrategy.DeviceCodeSignature(deviceCode)

	deviceAuthorizeRequest, err := d.DeviceCodeStorage.GetDeviceCodeSession(ctx, signature, request.GetSession())
	if errors.Is(err, fosite.ErrInvalidatedDeviceCode) {
		if deviceAuthorizeRequest == nil {
			return fosite.ErrServerError.
				WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
				WithDebug("GetDeviceAuthorizeSession must return a value for \"fosite.Requester\" when returning \"ErrInvalidatedDeviceCode\".")
		}

		// If a device code is used twice, we revoke all refresh and access tokens associated with this request.
		// reqID := authorizeRequest.GetID()
		hint := "The device code has already been used."
		debug := ""
		// if revErr := d.TokenRevocationStorage.RevokeAccessToken(ctx, reqID); revErr != nil {
		// 	hint += " Additionally, an error occurred during processing the access token revocation."
		// 	debug += "Revocation of access_token lead to error " + revErr.Error() + "."
		// }
		// if revErr := d.TokenRevocationStorage.RevokeRefreshToken(ctx, reqID); revErr != nil {
		// 	hint += " Additionally, an error occurred during processing the refresh token revocation."
		// 	debug += "Revocation of refresh_token lead to error " + revErr.Error() + "."
		// }
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint(hint).WithDebug(debug))
	}
	if err != nil && errors.Is(err, fosite.ErrNotFound) {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
	}
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// The authorization server MUST verify that the device code is valid
	// This needs to happen after store retrieval for the session to be hydrated properly
	if err := d.DeviceCodeStrategy.ValidateDeviceCode(ctx, request, deviceCode); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
	}

	// Check the state of authorisation
	if !deviceAuthorizeRequest.IsDeviceAuthorizationGranted() {
		return errorsx.WithStack(fosite.ErrAuthorizationPending)
	}

	if deviceAuthorizeRequest.IsDeviceAuthorizationDenied() {
		// do something
	}

	// Override scopes
	request.SetRequestedScopes(deviceAuthorizeRequest.GetRequestedScopes())

	// Override audiences
	request.SetRequestedAudience(deviceAuthorizeRequest.GetRequestedAudience())

	// The authorization server MUST ensure that the device code was issued to the authenticated
	// confidential client, or if the client is public, ensure that the
	// code was issued to "client_id" in the request,
	if deviceAuthorizeRequest.GetClient().GetID() != request.GetClient().GetID() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the one from the device authorize request."))
	}

	// Checking of POST client_id skipped, because:
	// If the client type is confidential or the client was issued client
	// credentials (or assigned other authentication requirements), the
	// client MUST authenticate with the authorization server as described
	// in Section 3.2.1.
	request.SetSession(deviceAuthorizeRequest.GetSession())
	request.SetID(deviceAuthorizeRequest.GetID())

	// requester.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(d.AccessTokenLifespan).Round(time.Second))
	// if d.RefreshTokenLifespan > -1 {
	// 	requester.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(d.RefreshTokenLifespan).Round(time.Second))
	// }

	return nil
}

// func canIssueRefreshToken(d *DeviceAuthorizationHandler, request fosite.Requester) bool {
// 	// Require one of the refresh token scopes, if set.
// 	if len(d.RefreshTokenScopes) > 0 && !request.GetGrantedScopes().HasOneOf(d.RefreshTokenScopes...) {
// 		return false
// 	}
// 	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
// 	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
// 		return false
// 	}
// 	return true
// }

func (d *DeviceAuthorizationHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !d.CanHandleTokenEndpointRequest(requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	deviceCode := requester.GetRequestForm().Get("device_code")
	signature := d.DeviceCodeStrategy.DeviceCodeSignature(deviceCode)

	authorizeRequest, err := d.DeviceCodeStorage.GetDeviceCodeSession(ctx, signature, requester.GetSession())
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if err := d.DeviceCodeStrategy.ValidateDeviceCode(ctx, requester, deviceCode); err != nil {
		// This needs to happen after store retrieval for the session to be hydrated properly
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithWrap(err).WithDebug(err.Error()))
	}

	for _, scope := range authorizeRequest.GetGrantedScopes() {
		requester.GrantScope(scope)
	}

	for _, audience := range authorizeRequest.GetGrantedAudience() {
		requester.GrantAudience(audience)
	}

	access, accessSignature, err := d.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	var refresh, refreshSignature string
	if d.canIssueRefreshToken(authorizeRequest) {
		refresh, refreshSignature, err = d.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	ctx, err = storage.MaybeBeginTx(ctx, d.CoreStorage)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if err := d.CoreStorage.InvalidateAuthorizeCodeSession(ctx, signature); err != nil {
		if rollBackTxnErr := storage.MaybeRollbackTx(ctx, d.CoreStorage); rollBackTxnErr != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
		}
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if err := d.CoreStorage.CreateAccessTokenSession(ctx, accessSignature, requester.Sanitize([]string{})); err != nil {
		if rollBackTxnErr := storage.MaybeRollbackTx(ctx, d.CoreStorage); rollBackTxnErr != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
		}
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if refreshSignature != "" {
		if err := d.CoreStorage.CreateRefreshTokenSession(ctx, refreshSignature, requester.Sanitize([]string{})); err != nil {
			if rollBackTxnErr := storage.MaybeRollbackTx(ctx, d.CoreStorage); rollBackTxnErr != nil {
				return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
			}
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	responder.SetAccessToken(access)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, d.AccessTokenLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	if refresh != "" {
		responder.SetExtra("refresh_token", refresh)
	}

	if err := storage.MaybeCommitTx(ctx, d.CoreStorage); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}

func (d *DeviceAuthorizationHandler) CanSkipClientAuth(requester fosite.AccessRequester) bool {
	return true
}

func (d *DeviceAuthorizationHandler) canIssueRefreshToken(request fosite.Requester) bool {
	// Require one of the refresh token scopes, if set.
	if len(d.RefreshTokenScopes) > 0 && !request.GetGrantedScopes().HasOneOf(d.RefreshTokenScopes...) {
		return false
	}
	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return false
	}
	return true
}

func (d *DeviceAuthorizationHandler) CanHandleTokenEndpointRequest(requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	return requester.GetGrantTypes().ExactOne(deviceCodeGrantType)
}