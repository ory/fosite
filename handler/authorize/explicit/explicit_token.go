package explicit

import (
	"github.com/go-errors/errors"
	"github.com/ory-am/common/pkg"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/enigma"
	. "github.com/ory-am/fosite/handler/authorize"
	"github.com/ory-am/fosite/handler/token"
	"golang.org/x/net/context"
	"net/http"
	"time"
)

// implements
// * https://tools.ietf.org/html/rfc6749#section-4.1.3 (everything)
func (c *AuthorizeExplicitEndpointHandler) HandleTokenEndpointRequest(_ context.Context, request AccessRequester, req *http.Request, session interface{}) error {
	// grant_type REQUIRED.
	// Value MUST be set to "authorization_code".
	if request.GetGrantType() != "authorize_code" {
		return nil
	}

	var authSess AuthorizeSession
	challenge := &enigma.Challenge{}
	challenge.FromString(req.Form.Get("code"))

	// code REQUIRED.
	// The authorization code received from the authorization server.
	if challenge.Key == "" || challenge.Signature == "" {
		return errors.New(ErrInvalidRequest)
	}

	// The authorization server MUST verify that the authorization code is valid
	if err := c.Generator.ValidateChallenge(request.GetClient().GetHashedSecret(), challenge); err != nil {
		return errors.New(ErrInvalidRequest)
	}

	ar, err := c.Store.GetAuthorizeCodeSession(challenge.Signature, &authSess)
	if err == pkg.ErrNotFound {
		return errors.New(ErrInvalidRequest)
	} else if err != nil {
		return errors.Wrap(err, 1)
	}

	// The authorization server MUST ensure that the authorization code was issued to the authenticated
	// confidential client, or if the client is public, ensure that the
	// code was issued to "client_id" in the request,
	if ar.GetClient().GetID() != request.GetClient().GetID() {
		return errors.New(ErrInvalidRequest)
	}

	// ensure that the "redirect_uri" parameter is present if the
	// "redirect_uri" parameter was included in the initial authorization
	// request as described in Section 4.1.1, and if included ensure that
	// their values are identical.
	if authSess.RequestRedirectURI != "" && (req.Form.Get("redirect_uri") != ar.GetRedirectURI().String()) {
		return errors.New(ErrInvalidRequest)
	}

	// If no lifespan has been set, reset to default lifespan
	if c.AuthCodeLifespan <= 0 {
		c.AuthCodeLifespan = authCodeDefaultLifespan
	}

	// https://tools.ietf.org/html/rfc6819#section-5.1.5.3]
	// A short expiration time for tokens is a means of protection against
	// the following threats: replay, token leak, online guessing
	if ar.GetRequestedAt().Add(c.AuthCodeLifespan).Before(time.Now()) {
		return errors.New(ErrInvalidRequest)
	}

	// Checking of client_id skipped, because:
	// If the client type is confidential or the client was issued client
	// credentials (or assigned other authentication requirements), the
	// client MUST authenticate with the authorization server as described
	// in Section 3.2.1.
	session = authSess.Extra
	return nil
}

func (c *AuthorizeExplicitEndpointHandler) HandleTokenEndpointResponse(ctx context.Context, responder AccessResponder, requester AccessRequester, req *http.Request, session interface{}) error {
	// grant_type REQUIRED.
	// Value MUST be set to "authorization_code".
	if requester.GetGrantType() != "authorize_code" {
		return nil
	}

	access, err := c.Generator.GenerateChallenge(requester.GetClient().GetHashedSecret())
	if err != nil {
		return errors.New(ErrServerError)
	}

	refresh, err := c.Generator.GenerateChallenge(requester.GetClient().GetHashedSecret())
	if err != nil {
		return errors.New(ErrServerError)
	}

	responder.SetAccessToken(access.String())
	responder.SetTokenType("bearer")
	responder.SetExtra("expires_in", int(c.AuthCodeLifespan.Seconds()))
	if err := c.Store.DeleteAuthorizeCodeSession(req.Form.Get("code")); err != nil {
		return errors.New(ErrServerError)
	}

	c.Store.CreateAccessTokenSession(access.Signature, requester, &token.TokenSession{})
	c.Store.CreateRefreshTokenSession(refresh.Signature, requester, &token.TokenSession{})
	return nil
}
