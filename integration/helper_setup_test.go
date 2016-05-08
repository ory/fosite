package integration_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/fosite-example/store"
	"github.com/ory-am/fosite/handler/core/strategy"
	idstrat "github.com/ory-am/fosite/handler/oidc/strategy"
	"github.com/ory-am/fosite/token/hmac"
	"github.com/ory-am/fosite/token/jwt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var fositeStore = &store.Store{
	Clients: map[string]*fosite.DefaultClient{
		"my-client": {
			ID:           "my-client",
			Secret:       []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
			RedirectURIs: []string{"http://localhost:3846/callback"},
			ResponseTypes:[]string{"id_token", "code", "token"},
			GrantTypes:   []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
		},
	},
	Users: map[string]store.UserRelation{
		"peter": {
			Username: "peter",
			Password: "foobar",
		},
	},
	AuthorizeCodes: map[string]fosite.Requester{},
	Implicit:       map[string]fosite.Requester{},
	AccessTokens:   map[string]fosite.Requester{},
	RefreshTokens:  map[string]fosite.Requester{},
	IDSessions:     map[string]fosite.Requester{},
}

var accessTokenLifespan = time.Hour

var refreshTokenLifespan = time.Hour

var idTokenLifespan = time.Hour

var accessCodeLifespan = time.Minute

func newOAuth2Client(ts *httptest.Server) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "my-client",
		ClientSecret: "foobar",
		RedirectURL:  ts.URL + "/callback",
		Scopes:       []string{"fosite"},
		Endpoint: oauth2.Endpoint{
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

var idTokenStrategy = &idstrat.DefaultStrategy{
	RS256JWTStrategy: &jwt.RS256JWTStrategy{
		PrivateKey: []byte(jwt.TestCertificates[0][1]),
		PublicKey:  []byte(jwt.TestCertificates[1][1]),
	},
}

var hmacStrategy = &strategy.HMACSHAStrategy{
	Enigma: &hmac.HMACStrategy{
		GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows"),
	},
}

func newFosite() *fosite.Fosite {
	f := fosite.NewFosite(fositeStore)
	return f
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
