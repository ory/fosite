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
	"github.com/ory-am/fosite/enigma/hmac"
	"github.com/ory-am/fosite/enigma/jwt"
	exampleStore "github.com/ory-am/fosite/fosite-example/store"
	"github.com/ory-am/fosite/handler/core"
	coreclient "github.com/ory-am/fosite/handler/core/client"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/ory-am/fosite/handler/core/implicit"
	"github.com/ory-am/fosite/handler/core/owner"
	"github.com/ory-am/fosite/handler/core/refresh"
	"github.com/ory-am/fosite/handler/core/strategy"
	"github.com/ory-am/fosite/handler/oidc"
	oidcexplicit "github.com/ory-am/fosite/handler/oidc/explicit"
	"github.com/ory-am/fosite/handler/oidc/hybrid"
	oidcimplicit "github.com/ory-am/fosite/handler/oidc/implicit"
	oidcstrategy "github.com/ory-am/fosite/handler/oidc/strategy"
	"github.com/parnurzeal/gorequest"
	goauth "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// This is an exemplary storage instance. We will add a client and a user to it so we can use these later on.
var store = &exampleStore.Store{
	IDSessions: make(map[string]Requester),
	Clients: map[string]*client.SecureClient{
		"my-client": {
			ID:           "my-client",
			Secret:       []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
			RedirectURIs: []string{"http://localhost:3846/callback"},
		},
	},
	Users: map[string]exampleStore.UserRelation{
		"peter": {
			// This store simply checks for equality, a real storage implementation would obviously use
			// a hashing algorithm for encrypting the user password.
			Username: "peter",
			Password: "foobar",
		},
	},
	AuthorizeCodes: map[string]Requester{},
	Implicit:       map[string]Requester{},
	AccessTokens:   map[string]Requester{},
	RefreshTokens:  map[string]Requester{},
}

// A valid oauth2 client (check the store) that additionally requests an OpenID Connect id token
var clientConf = goauth.Config{
	ClientID:     "my-client",
	ClientSecret: "foobar",
	RedirectURL:  "http://localhost:3846/callback",
	Scopes:       []string{"fosite", "openid"},
	Endpoint: goauth.Endpoint{
		TokenURL: "http://localhost:3846/token",
		AuthURL:  "http://localhost:3846/auth",
	},
}

// The same thing (valid oauth2 client) but for using the cliend credentials grant
var appClientConf = clientcredentials.Config{
	ClientID:     "my-client",
	ClientSecret: "foobar",
	Scopes:       []string{"fosite"},
	TokenURL:     "http://localhost:3846/token",
}

// You can decide if you want to use HMAC or JWT or another strategy for generating authorize codes and access / refresh tokens
var hmacStrategy = &strategy.HMACSHAStrategy{
	Enigma: &hmac.Enigma{
		GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows"),
	},
}

// You can decide if you want to use HMAC or JWT or another strategy for generating authorize codes and access / refresh tokens
// The JWT strategy is mandatory for issuing ID Tokens (OpenID Connect)
//
// NOTE One thing to keep in mind is that the power of JWT does not mean anything
// when used as an authorize token, since the authorize token really just should
// be a random string that is hard to guess.
var jwtStrategy = &strategy.JWTStrategy{
	Enigma: &jwt.Enigma{
		PrivateKey: []byte(jwt.TestCertificates[0][1]),
		PublicKey:  []byte(jwt.TestCertificates[1][1]),
	},
}

// This strategy is used for issuing OpenID Conenct id tokens
var idtokenStrategy = &oidcstrategy.JWTStrategy{
	Enigma: &jwt.Enigma{
		PrivateKey: []byte(jwt.TestCertificates[0][1]),
		PublicKey:  []byte(jwt.TestCertificates[1][1]),
	},
}

// Change below to change the signing method (hmacStrategy or jwtStrategy)
var selectedStrategy = hmacStrategy

// A session is passed from the `/auth` to the `/token` endpoint. You probably want to store data like: "Who made the request",
// "What organization does that person belong to" and so on.
// For our use case, the session will meet the requirements imposed by JWT access tokens, HMAC access tokens and OpenID Connect
// ID Tokens plus a custom field
type session struct {
	User string
	*strategy.JWTSession
	*oidcstrategy.IDTokenSession
}

// newSession is a helper function for creating a new session
func newSession(user string) *session {
	return &session{
		User: user,
		JWTSession: &strategy.JWTSession{
			JWTClaims: &jwt.Claims{
				Issuer:         "fosite.my-application.com",
				Subject:        user,
				Audience:       "*.my-application.com",
				ExpiresAt:      time.Now().Add(time.Hour * 6),
				IssuedAt:       time.Now(),
				NotValidBefore: time.Now(),
			},
			JWTHeader: &jwt.Header{
				Extra: make(map[string]interface{}),
			},
		},
		IDTokenSession: &oidcstrategy.IDTokenSession{
			IDClaims: &jwt.Claims{
				Issuer:         "fosite.my-application.com",
				Subject:        user,
				Audience:       "*.my-application.com",
				ExpiresAt:      time.Now().Add(time.Hour * 6),
				IssuedAt:       time.Now(),
				NotValidBefore: time.Now(),
			},
			IDToken: &jwt.Header{
				Extra: make(map[string]interface{}),
			},
		},
	}
}

// fositeFactory creates a new Fosite instance with all features enabled
func fositeFactory() OAuth2Provider {
	// Instantiate a new fosite instance
	f := NewFosite(store)

	// Set the default access token lifespan to one hour
	accessTokenLifespan := time.Hour

	// Most handlers are composable. This little helper is used by some of the handlers below.
	oauth2HandleHelper := &core.HandleHelper{
		AccessTokenStrategy: selectedStrategy,
		AccessTokenStorage:  store,
		AccessTokenLifespan: accessTokenLifespan,
	}

	// This handler is responsible for the authorization code grant flow
	explicitHandler := &explicit.AuthorizeExplicitGrantTypeHandler{
		AccessTokenStrategy:       selectedStrategy,
		RefreshTokenStrategy:      selectedStrategy,
		AuthorizeCodeStrategy:     selectedStrategy,
		AuthorizeCodeGrantStorage: store,
		AuthCodeLifespan:          time.Minute * 10,
		AccessTokenLifespan:       accessTokenLifespan,
	}
	// In order to "activate" the handler, we need to add it to fosite
	f.AuthorizeEndpointHandlers.Append(explicitHandler)

	// Because this handler both handles `/auth` and `/token` endpoint requests, we need to add him to
	// both registries.
	f.TokenEndpointHandlers.Append(explicitHandler)

	// This handler is responsible for the implicit flow. The implicit flow does not return an authorize code
	// but instead returns the access token directly via an url fragment.
	implicitHandler := &implicit.AuthorizeImplicitGrantTypeHandler{
		AccessTokenStrategy: selectedStrategy,
		AccessTokenStorage:  store,
		AccessTokenLifespan: accessTokenLifespan,
	}
	f.AuthorizeEndpointHandlers.Append(implicitHandler)

	// This handler is responsible for the client credentials flow. This flow is used when you want to
	// authorize a client instead of an user.
	clientHandler := &coreclient.ClientCredentialsGrantHandler{
		HandleHelper: oauth2HandleHelper,
	}
	f.TokenEndpointHandlers.Append(clientHandler)

	// This handler is responsible for the resource owner password credentials grant. In general, this
	// is a flow which should not be used but could be useful in legacy environments. It uses a
	// user's credentials (username, password) to issue an access token.
	ownerHandler := &owner.ResourceOwnerPasswordCredentialsGrantHandler{
		HandleHelper:                                 oauth2HandleHelper,
		ResourceOwnerPasswordCredentialsGrantStorage: store,
	}
	f.TokenEndpointHandlers.Append(ownerHandler)

	// This handler is responsible for the refresh token grant. This type is used when you want to exchange
	// a refresh token for a new refresh token and a new access token.
	refreshHandler := &refresh.RefreshTokenGrantHandler{
		AccessTokenStrategy:      selectedStrategy,
		RefreshTokenStrategy:     selectedStrategy,
		RefreshTokenGrantStorage: store,
		AccessTokenLifespan:      accessTokenLifespan,
	}
	f.TokenEndpointHandlers.Append(refreshHandler)

	// This helper is similar to oauth2HandleHelper but for OpenID Connect handlers.
	oidcHelper := &oidc.IDTokenHandleHelper{IDTokenStrategy: idtokenStrategy}

	// The OpenID Connect Authorize Code Flow.
	oidcExplicit := &oidcexplicit.OpenIDConnectExplicitHandler{
		OpenIDConnectRequestStorage: store,
		IDTokenHandleHelper:         oidcHelper,
	}
	f.AuthorizeEndpointHandlers.Append(oidcExplicit)
	// Because this handler both handles `/auth` and `/token` endpoint requests, we need to add him to
	// both registries.
	f.TokenEndpointHandlers.Append(oidcExplicit)

	// The OpenID Connect Implicit Flow.
	oidcImplicit := &oidcimplicit.OpenIDConnectImplicitHandler{
		IDTokenHandleHelper:               oidcHelper,
		AuthorizeImplicitGrantTypeHandler: implicitHandler,
	}
	f.AuthorizeEndpointHandlers.Append(oidcImplicit)

	// The OpenID Connect Hybrid Flow.
	oidcHybrid := &hybrid.OpenIDConnectHybridHandler{
		IDTokenHandleHelper:               oidcHelper,
		AuthorizeExplicitGrantTypeHandler: explicitHandler,
		AuthorizeImplicitGrantTypeHandler: implicitHandler,
	}
	f.AuthorizeEndpointHandlers.Append(oidcHybrid)

	// Add a request validator for Access Tokens to fosite
	f.AuthorizedRequestValidators.Append(&core.CoreValidator{
		AccessTokenStrategy: hmacStrategy,
		AccessTokenStorage:  store,
	})

	return f
}

// This is our fosite instance
var oauth2 = fositeFactory()

func main() {
	// Set up some endpoints. You could also use gorilla/mux or any other router.

	http.HandleFunc("/auth", authEndpoint)
	http.HandleFunc("/token", tokenEndpoint)

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.HandleFunc("/client", clientEndpoint)
	http.HandleFunc("/owner", ownerEndpoint)
	log.Fatal(http.ListenAndServe(":3846", nil))
}

func tokenEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := NewContext()

	// Create an empty session object which will be passed to the request handlers
	mySessionData := newSession("")

	// This will create an access request object and iterate through the registered TokenEndpointHandlers to validate the request.
	accessRequest, err := oauth2.NewAccessRequest(ctx, req, mySessionData)

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		log.Printf("Error occurred in NewAccessRequest: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
		oauth2.WriteAccessError(rw, accessRequest, err)
		return
	}

	// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
	// and aggregate the result in response.
	response, err := oauth2.NewAccessResponse(ctx, req, accessRequest)
	if err != nil {
		log.Printf("Error occurred in NewAccessResponse: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
		oauth2.WriteAccessError(rw, accessRequest, err)
		return
	}

	// All done, send the response.
	oauth2.WriteAccessResponse(rw, accessRequest, response)

	// The client now has a valid access token
}

func authEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := NewContext()

	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	ar, err := oauth2.NewAuthorizeRequest(ctx, req)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeRequest: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}
	// You have now access to authorizeRequest, Code ResponseTypes, Scopes ...

	// Normally, this would be the place where you would check if the user is logged in and gives his consent.
	// We're simplifying things and just checking if the request includes a valid username and password
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

	// Now that the user is authorized, we set up a session:
	mySessionData := newSession("peter")

	// It's also wise to check the requested scopes, e.g.:
	// if authorizeRequest.GetScopes().Has("admin") {
	//     http.Error(rw, "you're not allowed to do that", http.StatusForbidden)
	//     return
	// }

	// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
	// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
	// to support open id connect.
	response, err := oauth2.NewAuthorizeResponse(ctx, req, ar, mySessionData)

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeResponse: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	// Last but not least, send the response!
	oauth2.WriteAuthorizeResponse(rw, ar, response)
}

// *****************************************************************************
// some views for easier navigation
// *****************************************************************************

func homeHandler(rw http.ResponseWriter, req *http.Request) {
	rw.Write([]byte(fmt.Sprintf(`
		<p>You can obtain an access token using various methods</p>
		<ul>
			<li>
				<a href="%s">Authorize code grant (with OpenID Connect)</a>
			</li>
			<li>
				<a href="%s">Implicit grant (with OpenID Connect)</a>
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
		clientConf.AuthCodeURL("some-random-state-foobar")+"&nonce=some-random-nonce",
		"http://localhost:3846/auth?client_id=my-client&redirect_uri=http%3A%2F%2Flocalhost%3A3846%2Fcallback&response_type=token%20id_token&scope=fosite%20openid&state=some-random-state-foobar&nonce=some-random-nonce",
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

func typeof(v interface{}) string {
	return reflect.TypeOf(v).String()
}
