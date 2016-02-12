package fosite

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"golang.org/x/net/context"
)

func (c *Fosite) NewAuthorizeRequest(ctx context.Context, r *http.Request) (AuthorizeRequester, error) {
	if c.RequiredScope == "" {
		c.RequiredScope = DefaultRequiredScopeName
	}

	request := &AuthorizeRequest{
		ResponseTypes:        Arguments{},
		HandledResponseTypes: Arguments{},
		Request: Request{
			Scopes:      Arguments{},
			RequestedAt: time.Now(),
		},
	}

	if err := r.ParseForm(); err != nil {
		return request, errors.New(ErrInvalidRequest)
	}

	request.Form = r.Form

	client, err := c.Store.GetClient(r.Form.Get("client_id"))
	if err != nil {
		return request, errors.New(ErrInvalidClient)
	}
	request.Client = client

	// Fetch redirect URI from request
	rawRedirURI, err := GetRedirectURIFromRequestValues(r.Form)
	if err != nil {
		return request, errors.New(ErrInvalidRequest)
	}

	// Validate redirect uri
	redirectURI, err := MatchRedirectURIWithClientRedirectURIs(rawRedirURI, client)
	if err != nil {
		return request, errors.New(ErrInvalidRequest)
	} else if !IsValidRedirectURI(redirectURI) {
		return request, errors.New(ErrInvalidRequest)
	}
	request.RedirectURI = redirectURI

	// https://tools.ietf.org/html/rfc6749#section-3.1.1
	// Extension response types MAY contain a space-delimited (%x20) list of
	// values, where the order of values does not matter (e.g., response
	// type "a b" is the same as "b a").  The meaning of such composite
	// response types is defined by their respective specifications.
	responseTypes := removeEmpty(strings.Split(r.Form.Get("response_type"), " "))

	// Enable support of multiple response types. This is for example required by OpenID Connect.
	if !c.EnableHybridAuthorizationFlow && len(responseTypes) > 1 {
		return request, errors.New(ErrInvalidRequest)
	}

	request.ResponseTypes = responseTypes

	// rfc6819 4.4.1.8.  Threat: CSRF Attack against redirect-uri
	// The "state" parameter should be used to link the authorization
	// request with the redirect URI used to deliver the access token (Section 5.3.5).
	//
	// https://tools.ietf.org/html/rfc6819#section-4.4.1.8
	// The "state" parameter should not	be guessable
	state := r.Form.Get("state")
	if state == "" {
		return request, errors.New(ErrInvalidState)
	} else if len(state) < minStateLength {
		// We're assuming that using less then 6 characters for the state can not be considered "unguessable"
		return request, errors.New(ErrInvalidState)
	}
	request.State = state

	// Remove empty items from arrays
	request.Scopes = removeEmpty(strings.Split(r.Form.Get("scope"), " "))
	if !request.Scopes.Has(c.RequiredScope) {
		return request, errors.New(ErrInvalidScope)
	}
	request.GrantScope(c.RequiredScope)

	return request, nil
}
