package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"time"

	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/compose"
	exampleStore "github.com/ory-am/fosite/fosite-example/store"
	"github.com/ory-am/fosite/handler/core/strategy"
	oidcstrategy "github.com/ory-am/fosite/handler/oidc/strategy"
	"github.com/ory-am/fosite/token/jwt"
	"github.com/parnurzeal/gorequest"
	"github.com/pkg/errors"
	goauth "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// This is an exemplary storage instance. We will add a client and a user to it so we can use these later on.
var store = exampleStore.NewExampleStore()

var config = new(compose.Config)

// Because we are using oauth2 and open connect id, we use this little helper to combine the two in one
// variable.
var strat = compose.CommonStrategy{
	// alternatively you could use OAuth2Strategy: compose.NewOAuth2JWTStrategy(mustRSAKey())
	CoreStrategy: compose.NewOAuth2HMACStrategy(config, []byte("some-super-cool-secret-that-nobody-knows")),

	// open id connect strategy
	OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(mustRSAKey()),
}

var oauth2 = compose.Compose(
	config,
	store,
	strat,

	// enabled handlers
	compose.OAuth2AuthorizeExplicitFactory,
	compose.OAuth2AuthorizeImplicitFactory,
	compose.OAuth2ClientCredentialsGrantFactory,
	compose.OAuth2RefreshTokenGrantFactory,
	compose.OAuth2ResourceOwnerPasswordCredentialsFactory,

	// be aware that open id connect factories need to be added after oauth2 factories to work properly.
	compose.OpenIDConnectExplicit,
	compose.OpenIDConnectImplicit,
	compose.OpenIDConnectHybrid,
)

// A valid oauth2 client (check the store) that additionally requests an OpenID Connect id token
var clientConf = goauth.Config{
	ClientID:     "my-client",
	ClientSecret: "foobar",
	RedirectURL:  "http://localhost:3846/callback",
	Scopes:       []string{"photos", "openid", "offline"},
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

// A session is passed from the `/auth` to the `/token` endpoint. You probably want to store data like: "Who made the request",
// "What organization does that person belong to" and so on.
// For our use case, the session will meet the requirements imposed by JWT access tokens, HMAC access tokens and OpenID Connect
// ID Tokens plus a custom field
type session struct {
	User string
	*strategy.HMACSession
	*strategy.JWTSession
	*oidcstrategy.DefaultSession
}

func main() {
	// Set up some endpoints. You could also use gorilla/mux or any other router.
	http.HandleFunc("/auth", authEndpoint)
	http.HandleFunc("/token", tokenEndpoint)

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.HandleFunc("/client", clientEndpoint)
	http.HandleFunc("/owner", ownerEndpoint)

	http.HandleFunc("/protected-api", validateEndpoint)

	fmt.Printf("Please open your webbrowser at http://localhost:3846")
	_ = exec.Command("open", "http://localhost:3846").Run()
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
		log.Printf("Error occurred in NewAccessRequest: %s\nStack: \n%s", err, err.(stackTracer).StackTrace())
		oauth2.WriteAccessError(rw, accessRequest, err)
		return
	}

	// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
	// and aggregate the result in response.
	response, err := oauth2.NewAccessResponse(ctx, req, accessRequest)
	if err != nil {
		log.Printf("Error occurred in NewAccessResponse: %s\nStack: \n%s", err, err.(stackTracer).StackTrace())
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
		log.Printf("Error occurred in NewAuthorizeRequest: %s\nStack: \n%s", err, err.(stackTracer).StackTrace())
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

	// we allow issuing of refresh tokens per default
	if ar.GetRequestedScopes().Has("offline") {
		ar.GrantScope("offline")
	}
	if ar.GetRequestedScopes().Has("photos") {
		ar.GrantScope("photos")
	}

	// Now that the user is authorized, we set up a session:
	mySessionData := newSession("peter")

	// When using the HMACSHA strategy you must use something that implements the HMACSessionContainer.
	// It brings you the power of overriding the default values.
	//
	// mySessionData.HMACSession = &strategy.HMACSession{
	//	AccessTokenExpiry: time.Now().Add(time.Day),
	//	AuthorizeCodeExpiry: time.Now().Add(time.Day),
	// }
	//

	// If you're using the JWT strategy, there's currently no distinction between access token and authorize code claims.
	// Therefore, you both access token and authorize code will have the same "exp" claim. If this is something you
	// need let us know on github.
	//
	// mySessionData.JWTClaims.ExpiresAt = time.Now().Add(time.Day)

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
		log.Printf("Error occurred in NewAuthorizeResponse: %s\nStack: \n%s", err, err.(stackTracer).StackTrace())
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	// Last but not least, send the response!
	oauth2.WriteAuthorizeResponse(rw, ar, response)
}

func validateEndpoint(rw http.ResponseWriter, req *http.Request) {
	ctx := NewContext()
	mySessionData := newSession("peter")

	ar, err := oauth2.ValidateToken(ctx, req.URL.Query().Get("token"), AccessToken, mySessionData, "photos", "photos.create")
	if err != nil {
		fmt.Fprintf(rw, "<h1>An error occurred!</h1>%s", err.Error())
		return
	}

	fmt.Fprintf(rw, `<h1>Request authorized!</h1>
<ul>
	<li>Client: %s</li>
	<li>Granted scopes: %v</li>
	<li>Requested scopes: %v</li>
	<li>Session data: %v</li>
	<li>Requested at: %s</li>
</ul>
`, ar.GetClient().GetID(), ar.GetGrantedScopes(), ar.GetRequestedScopes(), mySessionData, ar.GetRequestedAt())
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
		clientConf.AuthCodeURL("some-random-state-foobar")+"&nonce=some-random-nonce",
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
				Access token (click to make <a href="%s">authorized call</a>):<br>
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
		"/protected-api?token="+token.AccessToken,
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
					<input type="text" name="username" placeholder="username"/> <small>try "peter"</small>
				</li>
				<li>
					<input type="password" name="password" placeholder="password"/> <small>try "secret"</small><br>
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

// a few simple helpers

func mustRSAKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	return key
}

type stackTracer interface {
	StackTrace() errors.StackTrace
}

// newSession is a helper function for creating a new session
func newSession(user string) *session {
	return &session{
		User: user,
		HMACSession: &strategy.HMACSession{
			AccessTokenExpiry: time.Now().Add(time.Minute * 30),
		},
		// The JWTSession will not be used unless the OAuth2 JWT strategy is being used instead of HMAC
		JWTSession: &strategy.JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Issuer:    "https://fosite.my-application.com",
				Subject:   user,
				Audience:  "https://my-client.my-application.com",
				ExpiresAt: time.Now().Add(time.Hour * 6),
				IssuedAt:  time.Now(),
			},
			JWTHeader: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
		},
		DefaultSession: &oidcstrategy.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Issuer:    "https://fosite.my-application.com",
				Subject:   user,
				Audience:  "https://my-client.my-application.com",
				ExpiresAt: time.Now().Add(time.Hour * 6),
				IssuedAt:  time.Now(),
			},
			Headers: &jwt.Headers{
				Extra: make(map[string]interface{}),
			},
		},
	}
}
