package fosite

import (
	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite/client"
	"golang.org/x/net/context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (c *Fosite) NewAuthorizeRequest(_ context.Context, r *http.Request) (AuthorizeRequester, error) {
	request := &AuthorizeRequest{
		RequestedAt:   time.Now(),
		ResponseTypes: Arguments{},
		Scopes:        Arguments{},
	}

	if err := r.ParseForm(); err != nil {
		return request, errors.New(ErrInvalidRequest)
	}

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

	return request, nil
}

// AuthorizeRequester represents an authorize request
type AuthorizeRequester interface {
	// GetResponseTypes returns the requested response types
	GetResponseTypes() Arguments

	// GetClient returns this request's client or nil
	GetClient() Client

	// GetScopes returns this request's scopes
	GetScopes() Arguments

	// GetState returns the request's state
	GetState() string

	// GetRequestedAt returns the time the request was issued
	GetRequestedAt() time.Time

	// GetRedirectURI returns the requested redirect URI
	GetRedirectURI() *url.URL

	// IsRedirectURIValid returns false if the redirect is not rfc-conform (i.e. missing client, not on white list,
	// or malformed)
	IsRedirectURIValid() bool
}

// AuthorizeRequest is an implementation of AuthorizeRequester
type AuthorizeRequest struct {
	ResponseTypes Arguments
	Client        Client
	Scopes        Arguments
	RedirectURI   *url.URL
	State         string
	RequestedAt   time.Time
}

func (d *AuthorizeRequest) IsRedirectURIValid() bool {
	if d.GetRedirectURI() == nil {
		return false
	}

	raw := d.GetRedirectURI().String()
	if d.GetClient() == nil {
		return false
	}

	redirectURI, err := MatchRedirectURIWithClientRedirectURIs(raw, d.GetClient())
	if err != nil {
		return false
	}
	return IsValidRedirectURI(redirectURI)
}

func (d *AuthorizeRequest) GetResponseTypes() Arguments {
	return d.ResponseTypes
}

func (d *AuthorizeRequest) GetClient() Client {
	return d.Client
}

func (d *AuthorizeRequest) GetScopes() Arguments {
	return d.Scopes
}

func (d *AuthorizeRequest) GetState() string {
	return d.State
}

func (d *AuthorizeRequest) GetRedirectURI() *url.URL {
	return d.RedirectURI
}

func (d *AuthorizeRequest) GetRequestedAt() time.Time {
	return d.RequestedAt
}
