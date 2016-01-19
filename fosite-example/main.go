package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"time"

	"github.com/go-errors/errors"
	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/enigma"
	"github.com/ory-am/fosite/enigma/jwthelper"
	"github.com/ory-am/fosite/fosite-example/internal"
	coreclient "github.com/ory-am/fosite/handler/core/client"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/ory-am/fosite/handler/core/implicit"
	"github.com/ory-am/fosite/handler/core/owner"
	"github.com/ory-am/fosite/handler/core/refresh"
	"github.com/ory-am/fosite/handler/core/strategy"
	"github.com/parnurzeal/gorequest"
	goauth "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var store = &internal.Store{
	Clients: map[string]client.Client{
		"my-client": &client.SecureClient{
			ID:           "my-client",
			Secret:       []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
			RedirectURIs: []string{"http://localhost:3846/callback"},
		},
	},
	Users: map[string]internal.UserRelation{
		"peter": {
			Username: "peter",
			Password: "foobar",
		},
	},
	AuthorizeCodes: map[string]Requester{},
	Implicit:       map[string]Requester{},
	AccessTokens:   map[string]Requester{},
	RefreshTokens:  map[string]Requester{},
}
var oauth2 = fositeFactory()
var clientConf = goauth.Config{
	ClientID:     "my-client",
	ClientSecret: "foobar",
	RedirectURL:  "http://localhost:3846/callback",
	Scopes:       []string{"fosite"},
	Endpoint: goauth.Endpoint{
		TokenURL: "http://localhost:3846/token",
		AuthURL:  "http://localhost:3846/auth",
	},
}
var appClientConf = clientcredentials.Config{
	ClientID:     "my-client",
	ClientSecret: "foobar",
	Scopes:       []string{"fosite"},
	TokenURL:     "http://localhost:3846/token",
}

var hmacStrategy = &strategy.HMACSHAStrategy{
	Enigma: &enigma.HMACSHAEnigma{
		GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows"),
	},
}

var jwtStrategy = &strategy.JWTStrategy{
	Enigma: &enigma.JWTEnigma{
		PrivateKey: []byte(enigma.TestCertificates[0][1]),
		PublicKey:  []byte(enigma.TestCertificates[1][1]),
	},
}

/*
NOTE One thing to keep in mind is that the power of JWT does not mean anything
     when used as an authorize token, since the authorize token really just should
		 be a random string that is hard to guess.

NOTE In a real life implementation with fosite using JWT, it's best practice to use HMAC
		 for all authorize strategies instead of JWT, but for the sake being, here
		 we use JWTStrategy for all generators.
*/

// Change below to change the signing method (hmacStrategy or jwtStrategy)
var selectedStrategy = hmacStrategy

type session struct {
	User string
}

func fositeFactory() OAuth2Provider {
	// NewMyStorageImplementation should implement all storage interfaces.

	f := NewFosite(store)
	accessTokenLifespan := time.Hour

	// Let's enable the explicit authorize code grant!
	explicitHandler := &explicit.AuthorizeExplicitGrantTypeHandler{
		AccessTokenStrategy:   selectedStrategy,
		RefreshTokenStrategy:  selectedStrategy,
		AuthorizeCodeStrategy: selectedStrategy,
		Store:               store,
		AuthCodeLifespan:    time.Minute * 10,
		AccessTokenLifespan: accessTokenLifespan,
	}
	f.AuthorizeEndpointHandlers.Add("code", explicitHandler)
	f.TokenEndpointHandlers.Add("code", explicitHandler)

	// Implicit grant type
	implicitHandler := &implicit.AuthorizeImplicitGrantTypeHandler{
		AccessTokenStrategy: selectedStrategy,
		Store:               store,
		AccessTokenLifespan: accessTokenLifespan,
	}
	f.AuthorizeEndpointHandlers.Add("implicit", implicitHandler)

	// Client credentials grant type
	clientHandler := &coreclient.ClientCredentialsGrantHandler{
		AccessTokenStrategy: selectedStrategy,
		Store:               store,
		AccessTokenLifespan: accessTokenLifespan,
	}
	f.TokenEndpointHandlers.Add("client", clientHandler)

	// Resource owner password credentials grant type
	ownerHandler := &owner.ResourceOwnerPasswordCredentialsGrantHandler{
		AccessTokenStrategy: selectedStrategy,
		Store:               store,
		AccessTokenLifespan: accessTokenLifespan,
	}
	f.TokenEndpointHandlers.Add("owner", ownerHandler)

	// Refresh grant type
	refreshHandler := &refresh.RefreshTokenGrantHandler{
		AccessTokenStrategy:  selectedStrategy,
		RefreshTokenStrategy: selectedStrategy,
		Store:                store,
		AccessTokenLifespan:  accessTokenLifespan,
	}
	f.TokenEndpointHandlers.Add("refresh", refreshHandler)

	return f
}

func main() {
	http.HandleFunc("/auth", authEndpoint)
	http.HandleFunc("/token", tokenEndpoint)

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.HandleFunc("/client", clientEndpoint)
	http.HandleFunc("/owner", ownerEndpoint)
	log.Fatal(http.ListenAndServe(":3846", nil))
}

func typeof(v interface{}) string {
	return reflect.TypeOf(v).String()
}

func tokenEndpoint(rw http.ResponseWriter, req *http.Request) {
	ctx := NewContext()

	if typeof(*selectedStrategy) == "strategy.JWTStrategy" {
		// JWT
		claims, _ := jwthelper.NewClaimsContext("fosite", "peter", "group0", "",
			time.Now().Add(time.Hour), time.Now(), time.Now(), make(map[string]interface{}))

		mySessionData := strategy.JWTSession{
			JWTClaimsCtx: *claims,
			JWTHeaders:   make(map[string]interface{}),
		}

		accessRequest, err := oauth2.NewAccessRequest(ctx, req, &mySessionData)
		if err != nil {
			log.Printf("Error occurred in NewAccessRequest: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
			oauth2.WriteAccessError(rw, accessRequest, err)
			return
		}

		response, err := oauth2.NewAccessResponse(ctx, req, accessRequest)
		if err != nil {
			log.Printf("Error occurred in NewAccessResponse: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
			oauth2.WriteAccessError(rw, accessRequest, err)
			return
		}

		oauth2.WriteAccessResponse(rw, accessRequest, response)
	} else {
		// HMAC
		mySessionData := session{}

		accessRequest, err := oauth2.NewAccessRequest(ctx, req, &mySessionData)
		if err != nil {
			log.Printf("Error occurred in NewAccessRequest: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
			oauth2.WriteAccessError(rw, accessRequest, err)
			return
		}

		response, err := oauth2.NewAccessResponse(ctx, req, accessRequest)
		if err != nil {
			log.Printf("Error occurred in NewAccessResponse: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
			oauth2.WriteAccessError(rw, accessRequest, err)
			return
		}

		oauth2.WriteAccessResponse(rw, accessRequest, response)
	}
}

func authEndpoint(rw http.ResponseWriter, req *http.Request) {
	ctx := NewContext()

	ar, err := oauth2.NewAuthorizeRequest(ctx, req)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeRequest: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	if req.Form.Get("username") != "peter" {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Write([]byte(`<h1>Login page</h1>`))
		rw.Write([]byte(`
			<p>Howdy! This is the log in page. For this example, it is enough to supply the username.</p>
			<form method="post">
				<input type="text" name="username" /> <small>try peter</small><br>
				<input type="submit">
			</form>
		`))
		return
	}

	// Normally, this would be the place where you would check if the user is logged in and gives his consent.
	// For this test, let's assume that the user exists, is logged in, and gives his consent...

	if typeof(*selectedStrategy) == "strategy.JWTStrategy" {
		// JWT
		claims, _ := jwthelper.NewClaimsContext("fosite", "peter", "group0", "",
			time.Now().Add(time.Hour), time.Now(), time.Now(), make(map[string]interface{}))

		mySessionData := strategy.JWTSession{
			JWTClaimsCtx: *claims,
			JWTHeaders:   make(map[string]interface{}),
		}

		response, err := oauth2.NewAuthorizeResponse(ctx, req, ar, &mySessionData)
		if err != nil {
			log.Printf("Error occurred in NewAuthorizeResponse: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
			oauth2.WriteAuthorizeError(rw, ar, err)
			return
		}
		oauth2.WriteAuthorizeResponse(rw, ar, response)

	} else {
		// HMAC
		mySessionData := session{User: "peter"}

		response, err := oauth2.NewAuthorizeResponse(ctx, req, ar, &mySessionData)
		if err != nil {
			log.Printf("Error occurred in NewAuthorizeResponse: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
			oauth2.WriteAuthorizeError(rw, ar, err)
			return
		}
		oauth2.WriteAuthorizeResponse(rw, ar, response)
	}
}

//
// some views for easier navigation
//

func homeHandler(rw http.ResponseWriter, req *http.Request) {
	rw.Write([]byte(fmt.Sprintf(`
		<p>You can obtain an access token using various methods</p>
		<ul>
			<li>
				<a href="%s">Authorize code grant</a>
			</li>
			<li>
				<a href="%s">Implicit grant</a>
			</li>
			<li>
				<a href="/client">Client credentials grant</a>
			</li>
			<li>
				<a href="/owner">Resource owner password credentials grant</a>
			</li>
			<li>
				<a href="%s">Refresh grant</a>. <small>You will first see the login screen which is required to obtain a valid refresh token.</small>
			</li>
			<li>
				<a href="%s">Make an invalid request</a>
			</li>
		</ul>`,
		clientConf.AuthCodeURL("some-random-state-foobar"),
		"http://localhost:3846/auth?client_id=my-client&redirect_uri=http%3A%2F%2Flocalhost%3A3846%2Fcallback&response_type=token&scope=fosite&state=some-random-state-foobar",
		clientConf.AuthCodeURL("some-random-state-foobar"),
		"/auth?client_id=my-client&scope=fosite&response_type=123&redirect_uri=http://localhost:3846/callback",
	)))
}

func callbackHandler(rw http.ResponseWriter, req *http.Request) {
	rw.Write([]byte(`<h1>Callback site</h1><a href="/">Go back</a>`))
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if req.URL.Query().Get("error") != "" {
		rw.Write([]byte(fmt.Sprintf(`<h1>Error!</h1>
			Error: %s<br>
			Description: %s<br>
			<br>`,
			req.URL.Query().Get("error"),
			req.URL.Query().Get("error_description"),
		)))
		return
	}

	if req.URL.Query().Get("refresh") != "" {
		_, body, errs := gorequest.New().Post(clientConf.Endpoint.TokenURL).SetBasicAuth(clientConf.ClientID, clientConf.ClientSecret).SendString(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {req.URL.Query().Get("refresh")},
			"scope":         {"fosite"},
		}.Encode()).End()
		if len(errs) > 0 {
			rw.Write([]byte(fmt.Sprintf(`<p>Could not refresh token %s</p>`, errs)))
			return
		}
		rw.Write([]byte(fmt.Sprintf(`<p>Got a response from the refresh grant:<br><code>%s</code></p>`, body)))
		return
	}

	if req.URL.Query().Get("code") == "" {
		rw.Write([]byte(fmt.Sprintf(`<p>Could not find the authorize code. If you've used the implicit grant, check the
			browser location bar for the
			access token <small><a href="http://en.wikipedia.org/wiki/Fragment_identifier#Basics">(the server side does not have access to url fragments)</a></small>
			</p>`,
		)))
		return
	}

	rw.Write([]byte(fmt.Sprintf(`<p>Amazing! You just got an authorize code!:<br><code>%s</code></p>
		<p>Click <a href="/">here to return</a> to the front page</p>`,
		req.URL.Query().Get("code"),
	)))

	token, err := clientConf.Exchange(goauth.NoContext, req.URL.Query().Get("code"))
	if err != nil {
		rw.Write([]byte(fmt.Sprintf(`<p>I tried to exchange the authorize code for an access token but it did not work but got error: %s</p>`, err.Error())))
		return
	}

	rw.Write([]byte(fmt.Sprintf(`<p>Cool! You are now a proud token owner.<br>
		<ul>
			<li>
				Access token:<br>
				<code>%s</code>
			</li>
			<li>
				Refresh token (click <a href="%s">here to use it</a>):<br>
				<code>%s</code>
			</li>
			<li>
				Extra info: <br>
				<code>%s</code>
			</li>
		</ul>`,
		token.AccessToken,
		"?refresh="+url.QueryEscape(token.RefreshToken),
		token.RefreshToken,
		token,
	)))
}

func clientEndpoint(rw http.ResponseWriter, req *http.Request) {
	rw.Write([]byte(fmt.Sprintf(`<h1>Client Credentials Grant</h1>`)))
	token, err := appClientConf.Token(goauth.NoContext)
	if err != nil {
		rw.Write([]byte(fmt.Sprintf(`<p>I tried to get a token but received an error: %s</p>`, err.Error())))
		return
	}
	rw.Write([]byte(fmt.Sprintf(`<p>Awesome, you just received an access token!<br><br>%s<br><br><strong>more info:</strong><br><br>%s</p>`, token.AccessToken, token)))
	rw.Write([]byte(`<p><a href="/">Go back</a></p>`))
}

func ownerEndpoint(rw http.ResponseWriter, req *http.Request) {
	rw.Write([]byte(fmt.Sprintf(`<h1>Resource Owner Password Credentials Grant</h1>`)))
	req.ParseForm()
	if req.Form.Get("username") == "" || req.Form.Get("password") == "" {
		rw.Write([]byte(`<form method="post">
			<ul>
				<li>
					<input type="text" name="username" placeholder="username"/> <small>try peter</small>
				</li>
				<li>
					<input type="password" name="password" placeholder="password"/> <small>try foobar</small><br>
				</li>
				<li>
					<input type="submit" />
				</li>
			</ul>
		</form>`))
		rw.Write([]byte(`<p><a href="/">Go back</a></p>`))
		return
	}

	token, err := clientConf.PasswordCredentialsToken(goauth.NoContext, req.Form.Get("username"), req.Form.Get("password"))
	if err != nil {
		rw.Write([]byte(fmt.Sprintf(`<p>I tried to get a token but received an error: %s</p>`, err.Error())))
		rw.Write([]byte(`<p><a href="/">Go back</a></p>`))
		return
	}
	rw.Write([]byte(fmt.Sprintf(`<p>Awesome, you just received an access token!<br><br>%s<br><br><strong>more info:</strong><br><br>%s</p>`, token.AccessToken, token)))
	rw.Write([]byte(`<p><a href="/">Go back</a></p>`))
}
