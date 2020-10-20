/*
 * Copyright © 2020 Bosch.IO, Germany
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
 * @author		Miguel Paulos Nunes <Miguel.PaulosNunes@bosch.io>, Olaf Märker <Olaf.Maerker@bosch.io>
 * @copyright 	2020 Bosch.IO, Germany
 * @license 	Apache-2.0
 *
 */

package oauth2

import (
	"context"
	"github.com/ory/fosite/storage"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
)

// TokenExchangeGrantHandler is a response handler for the Token Exchange grant
// as defined in https://tools.ietf.org/html/rfc8693
type TokenExchangeGrantHandler struct {
	AccessTokenStrategy      AccessTokenStrategy
	AccessTokenStorage       AccessTokenStorage
	AccessTokenLifespan      time.Duration
	ScopeStrategy            fosite.ScopeStrategy
	AudienceMatchingStrategy fosite.AudienceMatchingStrategy
	RefreshTokenStrategy     RefreshTokenStrategy
	RefreshTokenLifespan     time.Duration
	RefreshTokenScopes       []string
	CoreStrategy
	CoreStorage
	Store fosite.Storage
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc8693#section-2.1 (currently impersonation only)
func (c *TokenExchangeGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	// grant_type REQUIRED.
	// Value MUST be set to "urn:ietf:params:oauth:grant-type:token-exchange".
	if !request.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:token-exchange") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	// Check whether client is allowed to use token exchange
	client := request.GetClient()
	if !client.GetGrantTypes().Has("urn:ietf:params:oauth:grant-type:token-exchange") {
		return errors.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:token-exchange\"."))
	}

	// subject_token REQUIRED
	form := request.GetRequestForm()
	subjectToken := form.Get("subject_token")
	if subjectToken == "" {
		return errors.WithStack(fosite.ErrInvalidRequestObject.WithHintf("Mandatory parameter subject_token is missing."))
	}

	// subject_token_type REQUIRED
	subjectTokenType := form.Get("subject_token_type")
	if subjectTokenType == "" {
		return errors.WithStack(fosite.ErrInvalidRequestObject.WithHintf("Mandatory parameter subject_token_type is missing."))
	}

	if subjectTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		return errors.WithStack(fosite.ErrInvalidRequestObject.WithHintf("Currently only subject_token_type urn:ietf:params:oauth:token-type:access_token is supported"))
	}

	sig := c.CoreStrategy.AccessTokenSignature(subjectToken)
	or, err := c.CoreStorage.GetAccessTokenSession(ctx, sig, request.GetSession())
	if err != nil {
		return errors.WithStack(fosite.ErrRequestUnauthorized.WithDebug(err.Error()))
	} else if err := c.CoreStrategy.ValidateAccessToken(ctx, or, subjectToken); err != nil {
		return err
	}

	var delegatingClient fosite.Client = nil
	// reload client from storage to ensure that may_act is up to date in case of eventual revocation
	if or.GetDelegatingClient() == nil {
		// first exchange request has no delegating client set
		delegatingClient, err = c.Store.GetClient(ctx, or.GetClient().GetID())
	} else {
		delegatingClient, err = c.Store.GetClient(ctx, or.GetDelegatingClient().GetID())
	}

	if err != nil {
		errors.WithStack(fosite.ErrInvalidClient.WithHint("The delegating OAuth2 Client does not exist.").WithDebug(err.Error()))
	}

	// check if delegating client allows the current client to perform an exchange on its tokens
	if !delegatingClient.GetMayAct().HasOneOf(client.GetID()) {
		return errors.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to perform a token exchange for the given subject token."))
	}
	request.SetDelegatingClient(delegatingClient)

	for _, scope := range request.GetRequestedScopes() {
		if !c.ScopeStrategy(client.GetScopes(), scope) &&
			!c.ScopeStrategy(or.GetGrantedScopes(), scope) {
			return errors.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope \"%s\".", scope))
		}
	}

	if err := c.AudienceMatchingStrategy(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return err
	}

	if client.IsPublic() {
		return errors.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is marked as public and is thus not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:token-exchange\"."))
	}

	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(c.AccessTokenLifespan))
	if c.RefreshTokenLifespan > -1 {
		request.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(c.RefreshTokenLifespan).Round(time.Second))
	}
	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc8693#section-2.2 (currently impersonation only)
func (c *TokenExchangeGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	if !request.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:token-exchange") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("urn:ietf:params:oauth:grant-type:token-exchange") {
		return errors.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:token-exchange\"."))
	}

	token, signature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, request)
	if err != nil {
		return err
	} else if err := c.AccessTokenStorage.CreateAccessTokenSession(ctx, signature, request.Sanitize([]string{})); err != nil {
		return err
	}

	if request.GetGrantedScopes().HasOneOf(c.RefreshTokenScopes...) {
		refresh, refreshSignature, err := c.RefreshTokenStrategy.GenerateRefreshToken(ctx, request)
		if err != nil {
			return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
		}
		if refreshSignature != "" {
			if err := c.CoreStorage.CreateRefreshTokenSession(ctx, refreshSignature, request.Sanitize([]string{})); err != nil {
				if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.CoreStorage); rollBackTxnErr != nil {
					err = rollBackTxnErr
				}
				return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
			}
		}
		response.SetExtra("refresh_token", refresh)
	}

	response.SetAccessToken(token)
	response.SetTokenType("bearer")
	response.SetExpiresIn(getExpiresIn(request, fosite.AccessToken, c.AccessTokenLifespan, time.Now().UTC()))
	response.SetScopes(request.GetGrantedScopes())
	response.SetIssuedTokenType("urn:ietf:params:oauth:token-type:access_token")

	return nil
}
