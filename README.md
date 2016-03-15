# ![Fosite security first OAuth2 framework](fosite.png)

**The security first OAuth2 framework for [Google's Go Language](https://golang.org).**
Built simple, powerful and extensible. This library implements peer-reviewed [IETF RFC6749](https://tools.ietf.org/html/rfc6749),
counterfeits weaknesses covered in peer-reviewed [IETF RFC6819](https://tools.ietf.org/html/rfc6819) and countermeasures various database
attack scenarios, keeping your application safe when that hacker penetrates or leaks your database.

[![Build Status](https://travis-ci.org/ory-am/fosite.svg?branch=master)](https://travis-ci.org/ory-am/fosite?branch=master)
[![Coverage Status](https://coveralls.io/repos/ory-am/fosite/badge.svg?branch=master&service=github&foo)](https://coveralls.io/github/ory-am/fosite?branch=master)
[![Go Report Card](https://goreportcard.com/badge/ory-am/fosite)](https://goreportcard.com/report/ory-am/fosite)

Be aware that `go get github.com/ory-am/fosite` will give you the master branch, which is and always will be *nightly*.
Once releases roll out, you will be able to fetch a specific [fosite API version through gopkg.in](#installation).
As of now, no stable `v1` version exists.

During development, we reviewed the following open specifications:
* [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
* [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
* [The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
* [OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819)

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

  - [Motivation](#motivation)
  - [Example](#example)
  - [A word on quality](#a-word-on-quality)
  - [A word on security](#a-word-on-security)
  - [A word on extensibility](#a-word-on-extensibility)
  - [Usage](#usage)
    - [Installation](#installation)
    - [Exemplary Server Implementation](#exemplary-server-implementation)
    - [Exemplary [Authorization Endpoint](https://tools.ietf.org/html/rfc6749#section-3.1)](#exemplary-authorization-endpointhttpstoolsietforghtmlrfc6749section-31)
- [Please log in](#please-log-in)
    - [Exemplary [Token Endpoint](https://tools.ietf.org/html/rfc6749#section-3.2)](#exemplary-token-endpointhttpstoolsietforghtmlrfc6749section-32)
    - [Exemplary Storage Implementation](#exemplary-storage-implementation)
    - [Extensible handlers](#extensible-handlers)
  - [Develop fosite](#develop-fosite)
    - [Useful commands](#useful-commands)
  - [Hall of Fame](#hall-of-fame)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Motivation

Fosite was written because our OAuth2 and OpenID Connect service [**Hydra**](https://github.com/ory-am/hydra)
required a secure and extensible OAuth2 library. We had to realize that nothing matching our requirements
was out there, so we decided to build it ourselves.

## Example

The example does not have nice visuals but it should give you an idea of what you can do with Fosite and a few lines
of code.

![Authorize Code Grant](docs/authorize-code-grant.gif)

You can run this minimalistic example by doing

```
go get github.com/ory-am/fosite/fosite-example
go install github.com/ory-am/fosite/fosite-example
fosite-example
```

There should be a server listening on [localhost:3846](https://localhost:3846/). You can check out the example's
source code [here](fosite-example/main.go).

## A word on quality

We tried to set up as many tests as possible and test for as many cases covered in the RFCs as possible. But we are only
human. Please, feel free to add tests for the various cases defined in the OAuth2 RFCs 6749 and 6819 or any other cases that improve the tests.

**Everyone** writing an RFC conform test that breaks with the current implementation, will receive a place in the
[Hall of Fame](#hall-of-fame)!

## A word on security

Please be aware that Fosite only secures parts your server side security. You still need to secure your apps and clients, keep
your tokens safe, prevent CSRF attacks, ensure database security, use valid and strong TLS certificates and much more. If you need any help or advice feel free to contact our security staff through [our website](https://ory.am/)!

We have given the various specifications, especially [OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819#section-5.1.5.3),
a very close look and included everything we thought was in the scope of this framework. Here is a complete list
of things we implemented in Fosite:

* [No Cleartext Storage of Credentials](https://tools.ietf.org/html/rfc6819#section-5.1.4.1.3)
* [Encryption of Credentials](https://tools.ietf.org/html/rfc6819#section-5.1.4.1.4)
* [Use Short Expiration Time](https://tools.ietf.org/html/rfc6819#section-5.1.5.3)
* [Limit Number of Usages or One-Time Usage](https://tools.ietf.org/html/rfc6819#section-5.1.5.4)
* [Bind Token to Client id](https://tools.ietf.org/html/rfc6819#section-5.1.5.8)
* [Automatic Revocation of Derived Tokens If Abuse Is Detected](https://tools.ietf.org/html/rfc6819#section-5.2.1.1)
* [Binding of Refresh Token to "client_id"](https://tools.ietf.org/html/rfc6819#section-5.2.2.2)
* [Refresh Token Rotation](https://tools.ietf.org/html/rfc6819#section-5.2.2.3)
* [Revocation of Refresh Tokens](https://tools.ietf.org/html/rfc6819#section-5.2.2.4)
* [Validate Pre-Registered "redirect_uri"](https://tools.ietf.org/html/rfc6819#section-5.2.3.5)
* [Binding of Authorization "code" to "client_id"](https://tools.ietf.org/html/rfc6819#section-5.2.4.4)
* [Binding of Authorization "code" to "redirect_uri"](https://tools.ietf.org/html/rfc6819#section-5.2.4.6)
* [Opaque access tokens](https://tools.ietf.org/html/rfc6749#section-1.4)
* [Opaque refresh tokens](https://tools.ietf.org/html/rfc6749#section-1.5)
* [Ensure Confidentiality of Requests](https://tools.ietf.org/html/rfc6819#section-5.1.1)
  Fosite ensures that redirect URIs use https **except localhost** but you need to implement
  TLS for the token and auth endpoints yourself.

Not implemented yet:
* [Use of Asymmetric Cryptography](https://tools.ietf.org/html/rfc6819#section-5.1.4.1.5) - enigma should use asymmetric
  cryptography per default instead of HMAC-SHA (but support both).

Additionally, we added these safeguards:
* **Enforcing random states:** Without a random-looking state the request will fail.
* **Advanced Token Validation:** Tokens are layouted as `<key>.<signature>` where `<signature>` is created using HMAC-SHA256, a global secret
  and the client's secret. Read more about this workflow in the [proposal](https://github.com/ory-am/fosite/issues/11).
  This is what a token can look like:
  `/tgBeUhWlAT8tM8Bhmnx+Amf8rOYOUhrDi3pGzmjP7c=.BiV/Yhma+5moTP46anxMT6cWW8gz5R5vpC9RbpwSDdM=`
* **Enforging scopes:** By default, you always need to include the `fosite` scope or fosite will not execute the request
  properly. Obviously, you can change the scope to `basic` or `core` but be aware that you should use scopes if you use
  OAuth2.

Sections below [Section 5](https://tools.ietf.org/html/rfc6819#section-5)
that are not covered in the list above should be reviewed by you. If you think that a specific section should be something
that is covered in Fosite, feel free to create an [issue](https://github.com/ory-am/fosite/issues).

**It is strongly encouraged to use the handlers shipped with Fosite as they follow the specs and are well tested.**

## A word on extensibility

Fosite is extensible ... because OAuth2 is an extensible and flexible **framework**.
Fosite let's you register custom token and authorize endpoint handlers with the security that the requests
have been validated against the OAuth2 specs beforehand.
You can easily extend Fosite's capabilities. For example, if you want to provide OpenID Connect on top of your
OAuth2 stack, that's no problem. Or custom assertions, what ever you like and as long as it is secure. ;)

## Usage

There is an API documentation available at [godoc.org/ory-am/fosite](https://godoc.org/github.com/ory-am/fosite).

### Installation

You will need [Go](https://golang.org) installed on your machine and it is required that you have set up your
GOPATH environment variable. Fosite is being shipped through gopkg.in so new updates don't break your code.
To see a full list of available versions check [gopkg.in/ory-am/fosite.v0](https://gopkg.in/ory-am/fosite.v0).

Right now, there is only an unstable release versioned as the v0 branch:

```
go get gopkg.in/ory-am/fosite.v0
```

**Before you read ahead.**
Take a look at these real-life implementations:
* [tests](oauth2_integration_helper_test.go)
* [example app](fosite-example/main.go)

### Exemplary Server Implementation

```go
package main

import(
	"github.com/go-errors/errors"

	. "github.com/ory-am/fosite"
	
	// Import hmac strategy for enigma
	enigma "github.com/ory-am/fosite/enigma/hmac"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/ory-am/fosite/handler/core/implicit"
	"github.com/ory-am/fosite/handler/core/owner"
	"github.com/ory-am/fosite/handler/core/refresh"
	"github.com/ory-am/fosite/handler/core/strategy"
	"github.com/ory-am/fosite/handler/core/client"
	"log"
	"net/http"
	"time"
)

var hmacStrategy = &strategy.HMACSHAStrategy{
	Enigma: &enigma.Enigma{
		GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows"),
	},
}

var oauth2 = fositeFactory()

func main() {
    // Note that you MUST use http over TLS if you use OAuth2. Do not use OAuth2 otherwise.
    // This example does not implement TLS for simplicity.
	http.HandleFunc("/auth", authEndpoint)
	http.HandleFunc("/token", tokenEndpoint)
	log.Fatal(http.ListenAndServe(":3846", nil))
}

func fositeFactory() OAuth2Provider {
    // NewMyStorageImplementation should implement all storage interfaces.
    // You can find an exemplary implementation in ./fosite-example/internal/store.go
    var store = newMyStorageImplementation()

	f := NewFosite(store)
	accessTokenLifespan := time.Hour

	// Let's enable the explicit authorize code grant!
	explicitHandler := &explicit.AuthorizeExplicitGrantTypeHandler{
		AccessTokenStrategy:   hmacStrategy,
		RefreshTokenStrategy:  hmacStrategy,
		AuthorizeCodeStrategy: hmacStrategy,
		Store:               store,
		AuthCodeLifespan:    time.Minute * 10,
		AccessTokenLifespan: accessTokenLifespan,
	}
	f.AuthorizeEndpointHandlers.Append(explicitHandler)
	f.TokenEndpointHandlers.Append(explicitHandler)

	// Implicit grant type
	implicitHandler := &implicit.AuthorizeImplicitGrantTypeHandler{
		AccessTokenStrategy: hmacStrategy,
		Store:               store,
		AccessTokenLifespan: accessTokenLifespan,
	}
	f.AuthorizeEndpointHandlers.Append(implicitHandler)

	// Client credentials grant type
	clientHandler := &coreclient.ClientCredentialsGrantHandler{
		AccessTokenStrategy: hmacStrategy,
		Store:               store,
		AccessTokenLifespan: accessTokenLifespan,
	}
	f.TokenEndpointHandlers.Append(clientHandler)

	// Resource owner password credentials grant type
	ownerHandler := &owner.ResourceOwnerPasswordCredentialsGrantHandler{
		AccessTokenStrategy: hmacStrategy,
		Store:               store,
		AccessTokenLifespan: accessTokenLifespan,
	}
	f.TokenEndpointHandlers.Append(ownerHandler)

	// Refresh grant type
	refreshHandler := &refresh.RefreshTokenGrantHandler{
		AccessTokenStrategy:  hmacStrategy,
		RefreshTokenStrategy: hmacStrategy,
		Store:                store,
		AccessTokenLifespan:  accessTokenLifespan,
	}
	f.TokenEndpointHandlers.Append(refreshHandler)

    return f
}
// ...
```

### Exemplary [Authorization Endpoint](https://tools.ietf.org/html/rfc6749#section-3.1)

```go
// ...
type session struct {
	User string
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

    // you have now access to authorizeRequest, Code ResponseTypes, Scopes ...
    // and can show the user agent a login or consent page
    //
    // or, for example:
    // if authorizeRequest.GetScopes().Has("admin") {
    //     http.Error(rw, "you're not allowed to do that", http.StatusForbidden)
    //     return
    // }

	// Normally, this would be the place where you would check if the user is logged in and gives his consent.
	// We're simplifying things and just checking if the request includes a valid username and password
	if req.Form.Get("username") != "peter" || req.Form.Get("password") != "secret password" {
		rw.Write([]byte(`<h1>Please log in</h1>`))
		// ...
		return
	}

	// You MUST also get the user's consent which is left out here for simplicity.

    // Now it's time to persist some data. This session will be later available to us in the token endpoint.
    // So make sure to store things like the user id here.
    // The authorize request will be stored additionally, so no need to save scopes or similar things.
	sess := &session{User: "peter"}

	// Now we need to get an response.
	// This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
	// In our case (let's assume response_type=code), the AuthorizeExplicitGrantTypeHandler is going to handle the request.
	//
	// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
	// to support open id connect.
	response, err := oauth2.NewAuthorizeResponse(ctx, req, ar, sess)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeResponse: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

    // Last but not least, send the response!
	oauth2.WriteAuthorizeResponse(rw, ar, response)

    // Done! The client should now have a valid authorize code!
}

// ...
```

### Exemplary [Token Endpoint](https://tools.ietf.org/html/rfc6749#section-3.2)

```go
// ...
func tokenEndpoint(rw http.ResponseWriter, req *http.Request) {
    // This context will be passed to all methods.
	ctx := NewContext()

	// Remember the sesion data from before? Yup, that's going to be saved in here!
	var mySessionData session

    // This will create an access request object and iterate through the registered TokenEndpointHandlers to validate the request.
	accessRequest, err := oauth2.NewAccessRequest(ctx, req, &mySessionData)
	if err != nil {
		log.Printf("Error occurred in NewAccessRequest: %s\nStack: \n%s", err, err.(*errors.Error).ErrorStack())
		oauth2.WriteAccessError(rw, accessRequest, err)
		return
	}

    // Now we have access to mySessionData's populated values and can do crazy things.

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

	// Your client does now have a valid access token
}
```

### Exemplary Storage Implementation

Fosite does not ship a storage implementation yet. To get fosite running, you need to implement `github.com/ory-am/fosite.Storage`.
Additionally, most of the token / authorize endpoint handlers require a store as well. You could however use one struct
to implement all the signatures.

The following code is taken from [fosite-example/internal/store.go](fosite-example/internal/store.go) and a working example
of such a struct. This store is capable of supplying storage methods to all the OAuth2 [core handlers](handler/core).


```go
package internal

import (
	"github.com/go-errors/errors"
	"github.com/ory-am/common/pkg"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
)

type UserRelation struct {
	Username string
	Password string
}

// Store is an in memory storage.
type Store struct {
	Clients        map[string]client.Client
	AuthorizeCodes map[string]fosite.Requester
	AccessTokens   map[string]fosite.Requester
	Implicit       map[string]fosite.Requester
	RefreshTokens  map[string]fosite.Requester
	Users          map[string]UserRelation
}

func (s *Store) GetClient(id string) (client.Client, error) {
	cl, ok := s.Clients[id]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	return cl, nil
}

func (s *Store) CreateAuthorizeCodeSession(code string, req fosite.Requester) error {
	s.AuthorizeCodes[code] = req
	return nil
}

func (s *Store) GetAuthorizeCodeSession(code string, _ interface{}) (fosite.Requester, error) {
	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	return rel, nil
}

func (s *Store) DeleteAuthorizeCodeSession(code string) error {
	delete(s.AuthorizeCodes, code)
	return nil
}

func (s *Store) CreateAccessTokenSession(signature string, req fosite.Requester) error {
	s.AccessTokens[signature] = req
	return nil
}

func (s *Store) GetAccessTokenSession(signature string, _ interface{}) (fosite.Requester, error) {
	rel, ok := s.AccessTokens[signature]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	return rel, nil
}

func (s *Store) DeleteAccessTokenSession(signature string) error {
	delete(s.AccessTokens, signature)
	return nil
}

func (s *Store) CreateRefreshTokenSession(signature string, req fosite.Requester) error {
	s.RefreshTokens[signature] = req
	return nil
}

func (s *Store) GetRefreshTokenSession(signature string, _ interface{}) (fosite.Requester, error) {
	rel, ok := s.RefreshTokens[signature]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	return rel, nil
}

func (s *Store) DeleteRefreshTokenSession(signature string) error {
	delete(s.RefreshTokens, signature)
	return nil
}

func (s *Store) CreateImplicitAccessTokenSession(code string, req fosite.Requester) error {
	s.Implicit[code] = req
	return nil
}

func (s *Store) DoCredentialsAuthenticate(name string, secret string) error {
	rel, ok := s.Users[name]
	if !ok {
		return pkg.ErrNotFound
	}
	if rel.Password != secret {
		return errors.New("Invalid credentials")
	}
	return nil
}
```

### Extensible handlers

You can replace the Token and Authorize endpoint logic by modifying `Fosite.TokenEndpointHandlers` and
`Fosite.AuthorizeEndpointHandlers`.

Let's take the explicit authorize handler. He is responsible for handling the
[authorize code workflow](https://aaronparecki.com/articles/2012/07/29/1/oauth2-simplified#web-server-apps).

If you want to enable the handler able to handle this workflow, you can do this:

```go
var hmacStrategy = &strategy.HMACSHAStrategy{
	Enigma: &enigma.Enigma{
		GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows"),
	},
}

// var store = ...

f := NewFosite(store)
accessTokenLifespan := time.Hour

// Let's enable the explicit authorize code grant!
explicitHandler := &explicit.AuthorizeExplicitGrantTypeHandler{
    AccessTokenStrategy:   hmacStrategy,
    RefreshTokenStrategy:  hmacStrategy,
    AuthorizeCodeStrategy: hmacStrategy,
    Store:               store,
    AuthCodeLifespan:    time.Minute * 10,
    AccessTokenLifespan: accessTokenLifespan,
}

// Please note that order matters!
f.AuthorizeEndpointHandlers.Append(explicitHandler)
f.TokenEndpointHandlers.Append(explicitHandler)
```

As you probably noticed, there are two types of handlers, one for the [authorization */auth* endpoint](https://tools.ietf.org/html/rfc6749#section-3.1) and one for the [token
*/token* endpoint](https://tools.ietf.org/html/rfc6749#section-3.2). The `AuthorizeExplicitEndpointHandler` implements
API requirements for both endpoints, while, for example, the `AuthorizeImplicitEndpointHandler` only implements
the `AuthorizeEndpointHandler` API.

You can find a complete list of handlers inside the [handler directory](handler). A short list is documented here:

* `github.com/ory-am/fosite/handler/core/explicit.AuthorizeExplicitEndpointHandler` implements the
  [Authorization Code Grant](https://tools.ietf.org/html/rfc6749#section-4.1)
* `github.com/ory-am/fosite/handler/core/implicit.AuthorizeImplicitEndpointHandler` implements the
  [Implicit Grant](https://tools.ietf.org/html/rfc6749#section-4.2)
* `github.com/ory-am/fosite/handler/core/token/owner.TokenROPasswordCredentialsEndpointHandler` implements the
  [Resource Owner Password Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.3)
* `github.com/ory-am/fosite/handler/core/token/client.TokenClientCredentialsEndpointHandler` implements the
  [Client Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.4)

## Develop fosite

You need git and golang installed on your system.

```
go get github.com/ory-am/fosite -d
cd $GOPATH/src/ github.com/ory-am/fosite
git status
git remote add myfork <url-to-your-fork>
go test ./...
```

Simple, right? Now you are ready to go! Make sure to run `go test ./...` often, detecting problems with your code
rather sooner than later.

### Useful commands

**Create storage mocks**
```sh
mockgen -package internal -destination internal/storage.go github.com/ory-am/fosite Storage
mockgen -package internal -destination internal/authorize_code_storage.go github.com/ory-am/fosite/handler/core AuthorizeCodeStorage
mockgen -package internal -destination internal/access_token_storage.go github.com/ory-am/fosite/handler/core AccessTokenStorage
mockgen -package internal -destination internal/refresh_token_strategy.go github.com/ory-am/fosite/handler/core RefreshTokenStorage
mockgen -package internal -destination internal/core_client_storage.go github.com/ory-am/fosite/handler/core/client ClientCredentialsGrantStorage
mockgen -package internal -destination internal/core_explicit_storage.go github.com/ory-am/fosite/handler/core/explicit AuthorizeCodeGrantStorage
mockgen -package internal -destination internal/core_implicit_storage.go github.com/ory-am/fosite/handler/core/implicit ImplicitGrantStorage
mockgen -package internal -destination internal/core_owner_storage.go github.com/ory-am/fosite/handler/core/owner ResourceOwnerPasswordCredentialsGrantStorage
mockgen -package internal -destination internal/core_refresh_storage.go github.com/ory-am/fosite/handler/core/refresh RefreshTokenGrantStorage
mockgen -package internal -destination internal/oidc_id_token_storage.go github.com/ory-am/fosite/handler/oidc OpenIDConnectRequestStorage
```

**Create strategy mocks**
```sh
mockgen -package internal -destination internal/access_token_strategy.go github.com/ory-am/fosite/handler/core AccessTokenStrategy
mockgen -package internal -destination internal/refresh_token_strategy.go github.com/ory-am/fosite/handler/core RefreshTokenStrategy
mockgen -package internal -destination internal/authorize_code_strategy.go github.com/ory-am/fosite/handler/core AuthorizeCodeStrategy
mockgen -package internal -destination internal/id_token_strategy.go github.com/ory-am/fosite/handler/oidc OpenIDConnectTokenStrategy
```

**Create handler mocks**
```sh
mockgen -package internal -destination internal/authorize_handler.go github.com/ory-am/fosite AuthorizeEndpointHandler
mockgen -package internal -destination internal/token_handler.go github.com/ory-am/fosite TokenEndpointHandler
```

**Create stateful "context" mocks**
```sh
mockgen -package internal -destination internal/client.go github.com/ory-am/fosite/client Client
mockgen -package internal -destination internal/request.go github.com/ory-am/fosite Requester
mockgen -package internal -destination internal/access_request.go github.com/ory-am/fosite AccessRequester
mockgen -package internal -destination internal/access_response.go github.com/ory-am/fosite AccessResponder
mockgen -package internal -destination internal/authorize_request.go github.com/ory-am/fosite AuthorizeRequester
mockgen -package internal -destination internal/authorize_response.go github.com/ory-am/fosite AuthorizeResponder
```

## Hall of Fame

This place is reserved for the fearless bug hunters, reviewers and contributors (alphabetical order).

* [agtorre](https://github.com/agtorre):
  [contributions](https://github.com/ory-am/fosite/issues?q=author%3Aagtorre),
  [participations](https://github.com/ory-am/fosite/issues?q=commenter%3Aagtorre).
* [danielchatfield](https://github.com/danielchatfield):
  [contributions](https://github.com/ory-am/fosite/issues?q=author%3Adanielchatfield),
  [participations](https://github.com/ory-am/fosite/issues?q=commenter%3Adanielchatfield).
* [leetal](https://github.com/leetal):
  [contributions](https://github.com/ory-am/fosite/issues?q=author%3Aleetal),
  [participations](https://github.com/ory-am/fosite/issues?q=commenter%3Aleetal).

Find out more about the [author](https://aeneas.io/) of Fosite and Hydra, and the
[Ory Company](https://ory.am/).
