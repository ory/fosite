package main

import (
	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/enigma"
	"github.com/ory-am/fosite/fosite-example/internal"
	"github.com/ory-am/fosite/handler/authorize/explicit"
	goauth "golang.org/x/oauth2"
	"log"
	"net/http"
	"time"
)

var store = &internal.Store{
	Clients: map[string]client.Client{
		"my-client": &client.SecureClient{
			ID:           "my-client",
			Secret:       []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
			RedirectURIs: []string{"http://localhost:8080/callback"},
		},
	},
	AuthorizeCodes: map[string]internal.AuthorizeCodesRelation{},
	AccessTokens:   map[string]internal.AccessRelation{},
	RefreshTokens:  map[string]internal.AccessRelation{},
}
var oauth2 OAuth2Provider = fositeFactory()
var clientConf = goauth.Config{
	ClientID:     "my-client",
	ClientSecret: "foobar",
	RedirectURL:  "http://localhost:8080/callback",
	Scopes:       []string{"fosite"},
	Endpoint: goauth.Endpoint{
		TokenURL: "http://localhost:8080/token",
		AuthURL:  "http://localhost:8080/auth",
	},
}

type session struct {
	User string
}

func main() {

	http.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte(`<a href="` + clientConf.AuthCodeURL("some-random-state-foobar") + `">Click here to authorize</a><br>
		<br>
		You can also click <a href="/auth?client_id=my-client&scope=fosite&response_type=123&redirect_uri=http://localhost:8080/callback">here</a> to see what happens when you issue an invalid request.
		`))
	})
	http.HandleFunc("/callback", func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		if req.URL.Query().Get("error") != "" {
			rw.Write([]byte(`<h1>Error!</h1>
			Error: ` + req.URL.Query().Get("error") +
				`<br>
			Description: ` + req.URL.Query().Get("error_description") + `<br><br><a href="/">Go back</a>`))
			return
		}
		rw.Write([]byte(`Amazing! You just got an authorize code!: ` + req.URL.Query().Get("code") + `<br><br>`))

		token, err := clientConf.Exchange(goauth.NoContext, req.URL.Query().Get("code"))
		if err != nil {
			rw.Write([]byte(`I tried to exchange the authorize code for an access token but it did not work :(<br>got error: ` + err.Error()))
		} else {
			rw.Write([]byte(`Cool! You are now a proud token owner.<br>Access token: ` + token.AccessToken + `<br>Refresh token: ` + token.RefreshToken))
		}
	})
	http.HandleFunc("/auth", authEndpoint)
	http.HandleFunc("/token", tokenEndpoint)
	http.ListenAndServe(":3846", nil)
}

func tokenEndpoint(rw http.ResponseWriter, req *http.Request) {
	ctx := NewContext()
	var mySessionData session

	accessRequest, err := oauth2.NewAccessRequest(ctx, req, &mySessionData)
	if err != nil {
		oauth2.WriteAccessError(rw, accessRequest, err)
		return
	}

	response, err := oauth2.NewAccessResponse(ctx, req, accessRequest, &mySessionData)
	if err != nil {
		oauth2.WriteAccessError(rw, accessRequest, err)
		return
	}

	oauth2.WriteAccessResponse(rw, accessRequest, response)
}

func authEndpoint(rw http.ResponseWriter, req *http.Request) {
	ctx := NewContext()

	ar, err := oauth2.NewAuthorizeRequest(ctx, req)
	if err != nil {
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	if req.Form.Get("username") != "peter" {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Write([]byte(`Howdy! This is the log in page. For this example, it is enough to supply the username.<br>
		<form method="post">
			<input type="text" name="username" />
			<input type="submit">
		</form>
		<em>ps: I heard that user "peter" is a valid username so why not try his name ;) </em>`))
		return
	}

	// Normally, this would be the place where you would check if the user is logged in and gives his consent.
	// For this test, let's assume that the user exists, is logged in, and gives his consent...

	sess := &session{
		User: "peter",
	}

	response, err := oauth2.NewAuthorizeResponse(ctx, req, ar, sess)
	if err != nil {
		log.Printf("Error occurred in authorize response part: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	oauth2.WriteAuthorizeResponse(rw, ar, response)
}

func fositeFactory() OAuth2Provider {
	// NewMyStorageImplementation should implement all storage interfaces.

	f := NewFosite(store)
	accessTokenLifespan := time.Hour

	// Let's enable the explicit authorize code grant!
	explicitHandler := &explicit.AuthorizeExplicitEndpointHandler{
		Enigma:              &enigma.HMACSHAEnigma{GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows")},
		Store:               store,
		AuthCodeLifespan:    time.Minute * 10,
		AccessTokenLifespan: accessTokenLifespan,
	}
	f.AuthorizeEndpointHandlers.Add("code", explicitHandler)
	f.TokenEndpointHandlers.Add("code", explicitHandler)

	return f
}
