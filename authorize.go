package fosite

import (
	"net/http"
	"github.com/go-errors/errors"
	"net/url"
	"strings"
	"time"
)

type AuthorizeRequest interface {
	GetClient() Client
	GetScopes() []string
	GetTypes() []string
	GetRedirectURI() string
	GetState() string
	GetExpiration() int32
	GetExtra() interface{}

	Finish() error
	Write() error
}

// Authorize request information
type DefaultAuthorizeRequest struct {
	Types        []string
	Client      Client
	Scopes       []string
	RedirectURI string
	State       string
	Expiration int32
	Config *Config
}

type AuthorizeData struct {
	// Client information.
	Client Client

	// Authorization code.
	Code string

	// Token expiration in seconds.
	ExpiresIn int32

	// Requested scope.
	Scope string

	// Redirect Uri from request.
	RedirectUri string

	// State data from request.
	State string

	// CreatedAt defines when this request was created.
	CreatedAt time.Time

	// Extra data to be passed to storage. Not used by the library.
	Extra interface{}
}

func (c *Config) HandleAuthorize(r *http.Request, store Storage, ar AuthorizeRequest) (error) {
	if err := r.ParseForm(); err != nil {
		return nil, errors.Wrap(ErrInvalidRequest, 0)
	}

	redirectURI, err := url.QueryUnescape(r.Form.Get("redirect_uri"))
	if err != nil {
		return nil, errors.Wrap(ErrInvalidRequest, 0)
	}

	client, err := store.GetClient(r.Form.Get("client_id"))
	if err != nil {
		return nil, errors.Wrap(ErrInvalidClient, 0)
	}

	responseTypes := strings.Split(r.Form.Get("response_type"), " ")
	if !areResponseTypesValid(c, responseTypes) {
		return nil, errors.Wrap(ErrUnsupportedGrantType, 0)
	}

	if redirectURI == "" && len(client.GetRedirectURIs()) == 1 {
		redirectURI = client.GetRedirectURIs()[0]
	} else if !stringInSlice(redirectURI, client.GetRedirectURIs()) {
		return nil, errors.Wrap(ErrInvalidRequest, 0)
	}

	scopes := strings.Split(r.Form.Get("scope"), " ")
	state := r.Form.Get("state")

	return AuthorizeRequest{
		Types: responseTypes,
		Client: client,
		Scopes: scopes,
		State: state,
		Expiration: c.Lifetime,
		config: Config,
	}, nil
}

func (c *Config) ExchangeAuthorizeRequestForAccessToken() {

}

func (c *Config) PersistAndWriteAuthorizeCode(*AuthorizeRequest) {

}

func areResponseTypesValid(c *Config, responseTypes string) bool {
	if len(responseTypes) < 1 {
		return false
	}
	for _, responseType := range responseTypes {
		if !stringInSlice(responseType, c.AllowedAuthorizeResponseTypes) {
			return false
		}
	}
	return true
}

func stringInSlice(needle string, haystack []string) bool {
	for _, b := range haystack {
		if b == needle {
			return true
		}
	}
	return false
}