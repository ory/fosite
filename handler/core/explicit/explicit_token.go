package explicit

import (
	"github.com/go-errors/errors"
	"github.com/ory-am/common/pkg"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/handler/core"
	. "github.com/ory-am/fosite/handler/core"
	"golang.org/x/net/context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// implements
// * https://tools.ietf.org/html/rfc6749#section-4.1.3 (everything)
func (c *AuthorizeExplicitGrantTypeHandler) ValidateTokenEndpointRequest(ctx context.Context, r *http.Request, request AccessRequester) error {
	// grant_type REQUIRED.
	// Value MUST be set to "authorization_code".
	if request.GetGrantType() != "authorization_code" {
		return nil
	}

	// The authorization server MUST verify that the authorization code is valid
	signature, err := c.AuthorizeCodeStrategy.ValidateAuthorizeCode(r.PostForm.Get("code"), ctx, r, request)
	if err != nil {
		return errors.New(ErrInvalidRequest)
	}

	authorizeRequest, err := c.Store.GetAuthorizeCodeSession(signature)
	if err == pkg.ErrNotFound {
		return errors.New(ErrInvalidRequest)
	} else if err != nil {
		return errors.New(ErrServerError)
	}

	// Override scopes
	request.SetScopes(authorizeRequest.GetScopes())

	// The authorization server MUST ensure that the authorization code was issued to the authenticated
	// confidential client, or if the client is public, ensure that the
	// code was issued to "client_id" in the request,
	if authorizeRequest.GetClient().GetID() != request.GetClient().GetID() {
		return errors.New(ErrInvalidRequest)
	}

	// ensure that the "redirect_uri" parameter is present if the
	// "redirect_uri" parameter was included in the initial authorization
	// request as described in Section 4.1.1, and if included ensure that
	// their values are identical.
	if authorizeRequest.GetRequestForm().Get("redirect_uri") != r.PostForm.Get("redirect_uri") {
		return errors.New(ErrInvalidRequest)
	}

	// If no lifespan has been set, reset to default lifespan
	if c.AuthCodeLifespan <= 0 {
		c.AuthCodeLifespan = authCodeDefaultLifespan
	}

	// https://tools.ietf.org/html/rfc6819#section-5.1.5.3]
	// A short expiration time for tokens is a means of protection against
	// the following threats: replay, token leak, online guessing
	if authorizeRequest.GetRequestedAt().Add(c.AuthCodeLifespan).Before(time.Now()) {
		return errors.New(ErrInvalidRequest)
	}

	// Checking of POST client_id skipped, because:
	// If the client type is confidential or the client was issued client
	// credentials (or assigned other authentication requirements), the
	// client MUST authenticate with the authorization server as described
	// in Section 3.2.1.
	request.SetGrantTypeHandled("authorization_code")
	request.SetSession(authorizeRequest.GetSession())
	return nil
}

func (c *AuthorizeExplicitGrantTypeHandler) HandleTokenEndpointRequest(ctx context.Context, req *http.Request, requester AccessRequester, responder AccessResponder) error {
	// grant_type REQUIRED.
	// Value MUST be set to "authorization_code".
	if requester.GetGrantType() != "authorization_code" {
		return nil
	}

	access, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, req, requester)
	if err != nil {
		return errors.New(ErrServerError)
	}

	refresh, refreshSignature, err := c.RefreshTokenStrategy.GenerateRefreshToken(ctx, req, requester)
	if err != nil {
		return errors.New(ErrServerError)
	}

	accessRequest, err := c.Store.GetAuthorizeCodeSession(req.PostForm.Get("code"))
	if err != nil {
		// The signature has already been verified both cryptographically and with lookup. If lookup fails here
		// it is due to some internal error.
		return errors.New(ErrServerError)
	}

	if err := c.Store.DeleteAuthorizeCodeSession(req.PostForm.Get("code")); err != nil {
		return errors.New(ErrServerError)
	} else if err := c.Store.CreateAccessTokenSession(accessSignature, requester); err != nil {
		return errors.New(ErrServerError)
	} else if err := c.Store.CreateRefreshTokenSession(refreshSignature, requester); err != nil {
		return errors.New(ErrServerError)
	}

	responder.SetAccessToken(access)
	responder.SetTokenType("bearer")
	responder.SetExtra("expires_in", strconv.Itoa(int(c.AccessTokenLifespan/time.Second)))
	responder.SetExtra("refresh_token", refresh)
	responder.SetExtra("state", accessRequest.GetState())
	responder.SetExtra("scope", strings.Join(requester.GetGrantedScopes(), " "))
	return nil
}
