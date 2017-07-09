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

	return c.IssueExplicitIDToken(ctx, requester, responder)
}
