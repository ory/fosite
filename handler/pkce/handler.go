// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"

	"github.com/ory/x/errorsx"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

var _ fosite.TokenEndpointHandler = (*Handler)(nil)

type Handler struct {
	AuthorizeCodeStrategy oauth2.AuthorizeCodeStrategy
	Storage               PKCERequestStorage
	Config                interface {
		fosite.EnforcePKCEProvider
		fosite.EnforcePKCEForPublicClientsProvider
		fosite.EnablePKCEPlainChallengeMethodProvider
	}

	// Verifier validates the code_verifier's format and its match against a
	// bound code_challenge. If nil, DefaultCodeVerifierStrategy is used, which
	// enforces RFC 7636 as written. See CodeVerifierStrategy for when to
	// override this.
	Verifier CodeVerifierStrategy
}

var _ fosite.TokenEndpointHandler = (*Handler)(nil)

// codeVerifierStrategy returns Verifier, defaulting to
// DefaultCodeVerifierStrategy when unset.
func (c *Handler) codeVerifierStrategy() CodeVerifierStrategy {
	if c.Verifier == nil {
		return DefaultCodeVerifierStrategy{}
	}
	return c.Verifier
}

func (c *Handler) HandleAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	// This let's us define multiple response types, for example open id connect's id_token
	if !ar.GetResponseTypes().Has("code") {
		return nil
	}

	challenge := ar.GetRequestForm().Get("code_challenge")
	method := ar.GetRequestForm().Get("code_challenge_method")
	client := ar.GetClient()

	if err := c.validate(ctx, challenge, method, client); err != nil {
		return err
	}

	// We don't need a session if it's not enforced and the PKCE parameters are not provided by the client.
	if challenge == "" && method == "" {
		return nil
	}

	code := resp.GetCode()
	if len(code) == 0 {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("The PKCE handler must be loaded after the authorize code handler."))
	}

	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	if err := c.Storage.CreatePKCERequestSession(ctx, signature, ar.Sanitize([]string{
		"code_challenge",
		"code_challenge_method",
	})); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}

func (c *Handler) validate(ctx context.Context, challenge, method string, client fosite.Client) error {
	if len(challenge) == 0 {
		// If the server requires Proof Key for Code Exchange (PKCE) by OAuth
		// clients and the client does not send the "code_challenge" in
		// the request, the authorization endpoint MUST return the authorization
		// error response with the "error" value set to "invalid_request".  The
		// "error_description" or the response of "error_uri" SHOULD explain the
		// nature of error, e.g., code challenge required.
		return c.validateNoPKCE(ctx, client)
	}

	// If the server supporting PKCE does not support the requested
	// transformation, the authorization endpoint MUST return the
	// authorization error response with "error" value set to
	// "invalid_request".  The "error_description" or the response of
	// "error_uri" SHOULD explain the nature of error, e.g., transform
	// algorithm not supported.
	switch method {
	case "S256":
		break
	case "plain":
		fallthrough
	case "":
		if !c.Config.GetEnablePKCEPlainChallengeMethod(ctx) {
			return errorsx.WithStack(fosite.ErrInvalidRequest.
				WithHint("Clients must use code_challenge_method=S256, plain is not allowed.").
				WithDebug("The server is configured in a way that enforces PKCE S256 as challenge method for clients."))
		}
	default:
		return errorsx.WithStack(fosite.ErrInvalidRequest.
			WithHint("The code_challenge_method is not supported, use S256 instead."))
	}
	return nil
}

func (c *Handler) validateNoPKCE(ctx context.Context, client fosite.Client) error {
	if c.Config.GetEnforcePKCE(ctx) {
		return errorsx.WithStack(fosite.ErrInvalidRequest.
			WithHint("Clients must include a code_challenge when performing the authorize code flow, but it is missing.").
			WithDebug("The server is configured in a way that enforces PKCE for clients."))
	}
	if c.Config.GetEnforcePKCEForPublicClients(ctx) && client.IsPublic() {
		return errorsx.WithStack(fosite.ErrInvalidRequest.
			WithHint("This client must include a code_challenge when performing the authorize code flow, but it is missing.").
			WithDebug("The server is configured in a way that enforces PKCE for this client."))
	}
	return nil
}

func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	// code_verifier
	// REQUIRED.  Code verifier
	//
	// The "code_challenge_method" is bound to the Authorization Code when
	// the Authorization Code is issued.  That is the method that the token
	// endpoint MUST use to verify the "code_verifier".
	verifier := request.GetRequestForm().Get("code_verifier")

	code := request.GetRequestForm().Get("code")
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	pkceRequest, err := c.Storage.GetPKCERequestSession(ctx, signature, request.GetSession())

	nv := len(verifier)

	if errors.Is(err, fosite.ErrNotFound) {
		if nv == 0 {
			return c.validateNoPKCE(ctx, request.GetClient())
		}

		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("Unable to find initial PKCE data tied to this request").WithWrap(err).WithDebug(err.Error()))
	} else if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	challenge := pkceRequest.GetRequestForm().Get("code_challenge")
	method := pkceRequest.GetRequestForm().Get("code_challenge_method")
	client := pkceRequest.GetClient()
	if err := c.validate(ctx, challenge, method, client); err != nil {
		return err
	}

	nc := len(challenge)

	if !c.Config.GetEnforcePKCE(ctx) && nc == 0 && nv == 0 {
		// No challenge was bound and none is required, so this is a valid
		// non-PKCE exchange. Consume the session before allowing it through.
		return c.consumePKCERequestSession(ctx, signature)
	}

	// Validation. See DefaultCodeVerifierStrategy for the RFC 7636 rules this
	// applies by default, and CodeVerifierStrategy for how to change them.
	if err := c.codeVerifierStrategy().ValidateVerifierFormat(ctx, verifier); err != nil {
		return err
	} else if nc == 0 {
		// A verifier was presented against a session that never had a challenge
		// bound to it. There is nothing here a downgrade could exploit, so the
		// session is consumed before rejecting the request.
		if err := c.consumePKCERequestSession(ctx, signature); err != nil {
			return err
		}

		return errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("The PKCE code verifier was provided but the code challenge was absent from the authorization request."))
	}

	// The session is deleted only once the verifier is confirmed to match the
	// bound challenge below -- never beforehand, and never on a failed match.
	// Deleting it on a failed attempt would strip the challenge, after which
	// the same code could be replayed with no verifier at all, downgrading the
	// exchange to a non-PKCE one.
	if err := c.codeVerifierStrategy().ValidateChallenge(ctx, method, challenge, verifier); err != nil {
		return err
	}

	return c.consumePKCERequestSession(ctx, signature)
}

// consumePKCERequestSession deletes the PKCE request session tied to
// signature. Call this only once a request has been fully validated, or
// determined not to need PKCE at all -- see the downgrade note in
// HandleTokenEndpointRequest.
func (c *Handler) consumePKCERequestSession(ctx context.Context, signature string) error {
	if err := c.Storage.DeletePKCERequestSession(ctx, signature); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	return nil
}

func (c *Handler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	return nil
}

func (c *Handler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

func (c *Handler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "authorization_code"
	return requester.GetGrantTypes().ExactOne("authorization_code")
}
