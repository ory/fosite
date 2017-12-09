// Copyright © 2017 Aeneas Rekkas <aeneas+oss@aeneas.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openid

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/pkg/errors"
)

type OpenIDConnectRefreshHandler struct {
	*IDTokenHandleHelper
}

func (c *OpenIDConnectRefreshHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !request.GetGrantTypes().Exact("refresh_token") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	if !request.GetGrantedScopes().Has("openid") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return errors.WithStack(fosite.ErrInvalidGrant.WithDebug("The client is not allowed to use the authorization_code grant type"))
	}

	if !request.GetClient().GetResponseTypes().Has("id_token") {
		return errors.WithStack(fosite.ErrUnknownRequest.WithDebug("The client is not allowed to use response type id_token"))
	}

	sess, ok := request.GetSession().(Session)
	if !ok {
		return errors.New("Failed to generate id token because session must be of type fosite/handler/openid.Session")
	}

	// We need to reset the expires at value
	sess.IDTokenClaims().ExpiresAt = time.Time{}
	return nil
}

func (c *OpenIDConnectRefreshHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !requester.GetGrantTypes().Exact("refresh_token") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	if !requester.GetGrantedScopes().Has("openid") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	if !requester.GetClient().GetGrantTypes().Has("refresh_token") {
		return errors.WithStack(fosite.ErrInvalidGrant.WithDebug("The client is not allowed to use the authorization_code grant type"))
	}

	if !requester.GetClient().GetResponseTypes().Has("id_token") {
		return errors.WithStack(fosite.ErrUnknownRequest.WithDebug("The client is not allowed to use response type id_token"))
	}

	return c.IssueExplicitIDToken(ctx, requester, responder)
}
