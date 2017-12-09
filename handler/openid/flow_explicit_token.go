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

	"github.com/ory/fosite"
	"github.com/pkg/errors"
)

func (c *OpenIDConnectExplicitHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	return errors.WithStack(fosite.ErrUnknownRequest)
}

func (c *OpenIDConnectExplicitHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !requester.GetGrantTypes().Exact("authorization_code") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	authorize, err := c.OpenIDConnectRequestStorage.GetOpenIDConnectSession(ctx, requester.GetRequestForm().Get("code"), requester)
	if errors.Cause(err) == ErrNoSessionFound {
		return errors.WithStack(fosite.ErrUnknownRequest.WithDebug(err.Error()))
	} else if err != nil {
		return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
	}

	if !authorize.GetGrantedScopes().Has("openid") {
		return errors.WithStack(fosite.ErrMisconfiguration.WithDebug("The an openid connect session was found but the openid scope is missing in it"))
	}

	if !requester.GetClient().GetGrantTypes().Has("authorization_code") {
		return errors.WithStack(fosite.ErrInvalidGrant.WithDebug("The client is not allowed to use the authorization_code grant type"))
	}

	if !requester.GetClient().GetResponseTypes().Has("id_token") {
		return errors.WithStack(fosite.ErrInvalidGrant.WithDebug("The client is not allowed to use response type id_token"))
	}

	return c.IssueExplicitIDToken(ctx, authorize, responder)
}
