package fosite

import (
	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/generator"
	"golang.org/x/net/context"
	"net/http"
	"net/url"
	"strings"
)

// Authorize request information
type AuthorizeRequest struct {
	Types       []string
	Client      Client
	Scopes      []string
	RedirectURI string
	State       string
	Expiration  int32
	Code        *generator.Token
}

type ScopeStrategy interface {
}

// redirectFromValues extracts the redirect_uri from values.
// * rfc6749 3.1.   Authorization Endpoint
// * rfc6749 3.1.2. Redirection Endpoint
func (c *Config) redirectFromValues(values url.Values) (string, error) {
	// rfc6749 3.1.   Authorization Endpoint
	// The endpoint URI MAY include an "application/x-www-form-urlencoded" formatted (per Appendix B) query component
	redirectURI, err := url.QueryUnescape(values.Get("redirect_uri"))
	if err != nil {
		return "", errors.Wrap(ErrInvalidRequest, 0)
	}

	// rfc6749 3.1.2.  Redirection Endpoint
	// "The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3"
	if !(isValidURL(redirectURI)) {
		return "", errors.Wrap(ErrInvalidRequest, 0)
	}

	return redirectURI, nil
}

// redirectFromClient looks up if redirect and client are matching.
// * rfc6749 10.6.  Authorization Code Redirection URI Manipulation
// * rfc6819 4.4.1.7.  Threat: Authorization "code" Leakage through Counterfeit Client
func (c *Config) redirectFromClient(redirectURI string, client Client) (string, error) {
	// rfc6749 10.6.  Authorization Code Redirection URI Manipulation
	// The authorization server	MUST require public clients and SHOULD require confidential clients
	// to register their redirection URIs.  If a redirection URI is provided
	// in the request, the authorization server MUST validate it against the
	// registered value.
	//
	// rfc6819 4.4.1.7.  Threat: Authorization "code" Leakage through Counterfeit Client
	// The authorization server may also enforce the usage and validation
	// of pre-registered redirect URIs (see Section 5.2.3.5).
	if redirectURI == "" && len(client.GetRedirectURIs()) == 1 {
		if isValidURL(client.GetRedirectURIs()[0]) {
			return client.GetRedirectURIs()[0], nil
		}
	} else if stringInSlice(redirectURI, client.GetRedirectURIs()) {
		return redirectURI, nil
	}

	return "", errors.New(ErrInvalidRequest)
}

// NewAuthorizeRequest returns an AuthorizeRequest. This method makes rfc6749 compliant
// checks:
// * rfc6749 3.1.   Authorization Endpoint
// * rfc6749 3.1.1. Response Type
// * rfc6749 3.1.2. Redirection Endpoint
// * rfx6749 10.6.  Authorization Code Redirection URI Manipulation
//
// It also introduces countermeasures described in rfc6819:
// * rfc6819 4.4.1.7.  Threat: Authorization "code" Leakage through Counterfeit Client
// * rfc6819 4.4.1.8.  Threat: CSRF Attack against redirect-uri
func (c *Config) NewAuthorizeRequest(_ context.Context, r *http.Request, store Storage) (*AuthorizeRequest, error) {
	if err := r.ParseForm(); err != nil {
		return nil, errors.Wrap(ErrInvalidRequest, 0)
	}

	redirectURI, err := c.redirectFromValues(r.Form)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidRequest, 0)
	}

	client, err := c.Store.GetClient(r.Form.Get("client_id"))
	if err != nil {
		return nil, errors.Wrap(ErrInvalidClient, 0)
	}

	// * rfc6749 10.6.  Authorization Code Redirection URI Manipulation
	// * rfc6819 4.4.1.7.  Threat: Authorization "code" Leakage through Counterfeit Client
	if redirectURI, err = c.redirectFromClient(redirectURI, client); err != nil {
		return nil, errors.Wrap(ErrInvalidRequest, 0)
	}

	// rfc6749 3.1.1.  Response Type
	// response_type REQUIRED.
	// The value MUST be one of "code" for requesting an
	// authorization code as described by Section 4.1.1, "token" for
	// requesting an access token (implicit grant) as described by
	// Section 4.2.1, or a registered extension value as described by Section 8.4.
	//
	// response-type  = response-name *( SP response-name )
	// response-name  = 1*response-char
	// response-char  = "_" / DIGIT / ALPHA
	responseTypes := removeEmpty(strings.Split(r.Form.Get("response_type"), " "))
	if !areResponseTypesValid(c, responseTypes) {
		return nil, errors.Wrap(ErrUnsupportedGrantType, 0)
	}

	// rfc6819 4.4.1.8.  Threat: CSRF Attack against redirect-uri
	// The "state" parameter should be used to link the authorization
	// request with the redirect URI used to deliver the access token (Section 5.3.5).
	state := r.Form.Get("state")
	if state == "" {
		return nil, errors.Wrap(ErrInvalidRequest, 0)
	}

	code, err := c.AuthorizeCodeGenerator.Generate()
	if state == "" {
		return nil, errors.Wrap(ErrServerError, 0)
	}

	scopes := removeEmpty(strings.Split(r.Form.Get("scope"), " "))
	return &AuthorizeRequest{
		Types:       responseTypes,
		Client:      client,
		Scopes:      scopes,
		State:       state,
		Expiration:  c.Lifetime,
		RedirectURI: redirectURI,
		Code:        code,
	}, nil
}

func (c *Config) WriteAuthError(rw http.ResponseWriter, req *http.Request, err error) {
	redirectURI, err := c.redirectFromValues(req.Form)
	if err != nil {
		http.Error(rw, errInvalidRequestName, http.StatusBadRequest)
		return
	}

	client, err := c.Store.GetClient(req.Form.Get("client_id"))
	if err != nil {
		http.Error(rw, errInvalidRequestName, http.StatusBadRequest)
		return
	}

	// * rfc6749 10.6.  Authorization Code Redirection URI Manipulation
	// * rfc6819 4.4.1.7.  Threat: Authorization "code" Leakage through Counterfeit Client
	if redirectURI, err = c.redirectFromClient(redirectURI, client); err != nil {
		http.Error(rw, errInvalidRequestName, http.StatusBadRequest)
		return
	}

	redir, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(rw, errInvalidRequestName, http.StatusBadRequest)
		return
	}

	query := redir.Query()
	query.Add("error", err.Error())
	query.Add("description", err.Error())
	redir.RawQuery = query.Encode()
	rw.Header().Add("Location", redir.String())
	rw.WriteHeader(http.StatusFound)
}
