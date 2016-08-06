package integration_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/ory-am/fosite"
	store "github.com/ory-am/fosite/fosite-example/pkg"
	"github.com/ory-am/fosite/handler/oauth2"
	"github.com/ory-am/fosite/handler/openid"
	"github.com/ory-am/fosite/token/hmac"
	goauth "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var fositeStore = &store.Store{
	Clients: map[string]*fosite.DefaultClient{
		"my-client": {
			ID:            "my-client",
			Secret:        []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
			RedirectURIs:  []string{"http://localhost:3846/callback"},
			ResponseTypes: []string{"id_token", "code", "token"},
			GrantTypes:    []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
			Scopes:        []string{"fosite", "offline", "openid"},
		},
	},
	Users: map[string]store.UserRelation{
		"peter": {
			Username: "peter",
			Password: "secret",
		},
	},
	AuthorizeCodes: map[string]fosite.Requester{},
	Implicit:       map[string]fosite.Requester{},
	AccessTokens:   map[string]fosite.Requester{},
	RefreshTokens:  map[string]fosite.Requester{},
	IDSessions:     map[string]fosite.Requester{},
}

type defaultSession struct {
	*openid.DefaultSession
	*oauth2.HMACSession
}

var accessTokenLifespan = time.Hour

var authCodeLifespan = time.Minute

func newOAuth2Client(ts *httptest.Server) *goauth.Config {
	return &goauth.Config{
		ClientID:     "my-client",
		ClientSecret: "foobar",
		RedirectURL:  ts.URL + "/callback",
		Scopes:       []string{"fosite"},
		Endpoint: goauth.Endpoint{
			TokenURL: ts.URL + "/token",
			AuthURL:  ts.URL + "/auth",
		},
	}
}

func newOAuth2AppClient(ts *httptest.Server) *clientcredentials.Config {
	return &clientcredentials.Config{
		ClientID:     "my-client",
		ClientSecret: "foobar",
		Scopes:       []string{"fosite"},
		TokenURL:     ts.URL + "/token",
	}
}

var hmacStrategy = &oauth2.HMACSHAStrategy{
	Enigma: &hmac.HMACStrategy{
		GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows"),
	},
	AccessTokenLifespan:   accessTokenLifespan,
	AuthorizeCodeLifespan: authCodeLifespan,
}

func mockServer(t *testing.T, f fosite.OAuth2Provider, session interface{}) *httptest.Server {
	router := mux.NewRouter()
	router.HandleFunc("/auth", authEndpointHandler(t, f, session))
	router.HandleFunc("/token", tokenEndpointHandler(t, f))
	router.HandleFunc("/callback", authCallbackHandler(t))
	router.HandleFunc("/info", tokenInfoHandler(t, f, session))
	ts := httptest.NewServer(router)
	return ts
}
