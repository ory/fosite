# ![Fosite security first OAuth2 framework](fosite.png)

**The security first OAuth2 framework for [Google's Go Language](https://golang.org).**
Built simple, powerful and extensible. This library implements peer-reviewed [IETF RFC6749](https://tools.ietf.org/html/rfc6749),
counterfeits weaknesses covered in peer-reviewed [IETF RFC6819](https://tools.ietf.org/html/rfc6819) and countermeasures various database
attack scenarios, keeping your application safe when that hacker penetrates and leaks your database.

[![Build Status](https://travis-ci.org/ory-am/fosite.svg?branch=master)](https://travis-ci.org/ory-am/fosite?branch=master)
[![Coverage Status](https://coveralls.io/repos/ory-am/fosite/badge.svg?branch=master&service=github&foo)](https://coveralls.io/github/ory-am/fosite?branch=master)

Be aware that `go get github.com/ory-am/fosite` will give you the master branch, which is and always will be *nightly*.
Once releases roll out, you will be able to fetch a specific [fosite API version through gopkg.in](#installation).
As of now, no stable `v1` version exists.

During development, we took reviewed the following open specifications:
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
  - [Exemplary [Authorization Endpoint](https://tools.ietf.org/html/rfc6749#section-3.1)](#exemplary-authorization-endpointhttpstoolsietforghtmlrfc6749section-31)
  - [Exemplary [Token Endpoint](https://tools.ietf.org/html/rfc6749#section-3.2)](#exemplary-token-endpointhttpstoolsietforghtmlrfc6749section-32)
  - [Extensible handlers](#extensible-handlers)
  - [Replaceable storage](#replaceable-storage)
- [Develop fosite](#develop-fosite)
  - [Useful commands](#useful-commands)
- [Hall of Fame](#hall-of-fame)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Motivation

Fosite was written because our OAuth2 and OpenID Connect service [Hydra](https://github.com/ory-am/hydra)
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
source code [here](/fosite-example/main.go).

## A word on quality

We tried to set up as many tests as possible and test for as many cases covered in the RFCs as possible. But we are only
human. Please, feel free to add tests for the various cases defined in the OAuth2 RFCs 6749 and 6819.

**Everyone** writing an RFC conform test that breaks with the current implementation, will receive a place in the
[Hall of Fame](#hall-of-fame)!

## A word on security

Please be aware that Fosite only secures your server side security. You still need to secure your apps and clients, keep
your tokens safe, prevent CSRF attacks and much more. If you need any help or advice feel free to contact our security
staff through [our website](https://ory.am/)!

We have given the [OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819#section-5.1.5.3)
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

It is strongly encouraged to use the handlers shipped with Fosite as the follow specs.

Sections below [Section 5](https://tools.ietf.org/html/rfc6819#section-5)
that are not covered in the list above should be reviewed by you. If you think that a specific section should be something
that is covered in Fosite, feel free to create an [issue](https://github.com/ory-am/fosite/issues).

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
go get gopkg.in/ory-am/fosite.v0/...
```

### Exemplary [Authorization Endpoint](https://tools.ietf.org/html/rfc6749#section-3.1)

```go
package main

import(
    "github.com/ory-am/fosite"
    "github.com/ory-am/handler/core/explicit"
	"golang.org/x/net/context"
)

func fositeFactory() fosite.OAuth2Provider {
    // NewMyStorageImplementation should implement all storage interfaces.
    var store = newMyStorageImplementation()

    f := fosite.NewFosite(store)
    accessTokenLifespan := time.Hour

    // Let's enable the explicit authorize code grant!
    explicitHandler := &explicit.AuthorizeExplicitGrantTypeHandler struct {
        Enigma:           &enigma.HMACSHAEnigma{GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows")},
        Store:            store,
        AuthCodeLifespan: time.Minute * 10,
    }
    f.AuthorizeEndpointHandlers.Add("code", explicitHandler)
    f.TokenEndpointHandlers.Add("code", explicitHandler)

    // Next let's enable the implicit one!
    explicitHandler := &implicit.AuthorizeImplicitGrantTypeHandler struct {
        Enigma:              &enigma.HMACSHAEnigma{GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows")},
        Store:               store,
        AccessTokenLifespan: accessTokenLifespan,
    }
    f.AuthorizeEndpointHandlers.Add("implicit", implicitHandler)

    return f
}

// Let's assume that we're in a http handler
func handleAuth(rw http.ResponseWriter, r *http.Request) {
    ctx := fosite.NewContext()

    // Let's create an AuthorizeRequest object!
    // It will analyze the request and extract important information like scopes, response type and others.
    authorizeRequest, err := oauth2.NewAuthorizeRequest(ctx, r)
    if err != nil {
       oauth2.WriteAuthorizeError(rw, req, err)
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

    // it would also be possible to redirect the user to an identity provider (google, microsoft live, ...) here
    // and do fancy stuff like OpenID Connect amongst others

    // Once you have confirmed the users identity and consent that he indeed wants to give app XYZ authorization,
    // you will use the user's id to create an authorize session
    user := "12345"

    // mySessionData is going to be persisted alongside the other data. Note that mySessionData is arbitrary.
    // You will however absolutely need the user id later on, so at least store that!
    mySessionData := struct {
        User string
        UsingIdentityProvider string
        Foo string
    } {
        User: user,
        UsingIdentityProvider: "google",
        Foo: "bar",
    }

    // if you want to support OpenID Connect, this would be a good place to do stuff like
    // user := getUserFromCookie()
    // mySessionData := NewImplementsOpenIDSession()
    // if authorizeRequest.GetScopes().Has("openid") {
    //     if authorizeRequest.GetScopes().Has("email") {
    //         mySessionData.AddField("email", user.Email)
    //     }
    //     mySessionData.AddField("id", user.ID)
    // }
    //

    // Now is the time to handle the response types
    // You can use a custom list of response type handlers by setting
    // oauth2.AuthorizeEndpointHandlers = []fosite.AuthorizeEndpointHandler{}
    //
    // Each AuthorizeEndpointHandler is responsible for managing his own state data. For example, the code response type
    // handler stores the access token and the session data in a database backend and retrieves it later on
    // when handling a grant type.
    //
    // If you use advanced AuthorizeEndpointHandlers it is a good idea to read the README first and check if your
    // session object needs to implement any interface. Think of the session as a persistent context
    // for the handlers.
    response, err := oauth2.NewAuthorizeResponse(ctx, req, authorizeRequest, &mySessionData)
    if err != nil {
       oauth2.WriteAuthorizeError(rw, req, err)
       return
    }

    // The next step is going to redirect the user by either using implicit or explicit grant or both (for OpenID connect)
    oauth2.WriteAuthorizeResponse(rw, authorizeRequest, response)

    // Done! The client should now have a valid authorize code!
}

// ...
```

### Exemplary [Token Endpoint](https://tools.ietf.org/html/rfc6749#section-3.2)

```go
// ...

func handleToken(rw http.ResponseWriter, req *http.Request) {
    ctx := NewContext()

    // First we need to define a session object. Some handlers might require the session to implement
    // a specific interface, so keep that in mind when using them.
    var mySessionData struct {
        User string
        UsingIdentityProvider string
        Foo string
    }

    // This will create an access request object and iterate through the registered TokenEndpointHandlers.
    // These might populate mySessionData so do not pass nils.
    accessRequest, err := oauth2.NewAccessRequest(ctx, req, &mySessionData)
    if err != nil {
       oauth2.WriteAccessError(rw, accessRequest, err)
       return
    }

    // Now we have access to mySessionData's populated values and can do crazy things.

    // Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
    // and aggregate the result in response.
    response, err := oauth2.NewAccessResponse(ctx, req, accessRequest, &mySessionData)
    if err != nil {
       oauth2.WriteAccessError(rw, accessRequest, err)
       return
    }

    // All done, send the response.
    oauth2.WriteAccessResponse(rw, accessRequest, response)
}
```

### Extensible handlers

You can replace the Token and Authorize endpoint logic by modifying `Fosite.TokenEndpointHandlers` and
`Fosite.AuthorizeEndpointHandlers`.

Let's take the explicit authorize handler. He is responsible for handling the
[authorize code workflow](https://aaronparecki.com/articles/2012/07/29/1/oauth2-simplified#web-server-apps).

If you want to enable the handler able to handle this workflow, you can do this:

```go
handler := &explicit.AuthorizeExplicitGrantTypeHandler{
	Generator: &enigma.HMACSHAEnigma{GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows")},
	Store:     myCodeStore, // Needs to implement CodeResponseTypeStorage
}
oauth2 := &fosite.Fosite{
	AuthorizeEndpointHandlers: fosite.AuthorizeEndpointHandlers{
		handler,
	},
	TokenEndpointHandlers: fosite.TokenEndpointHandlers{
		handler,
	},
}
```

As you probably noticed, there are two types of handlers, one for the [authorization */auth* endpoint](https://tools.ietf.org/html/rfc6749#section-3.1) and one for the [token
*/token* endpoint](https://tools.ietf.org/html/rfc6749#section-3.2). The `AuthorizeExplicitEndpointHandler` implements
API requirements for both endpoints, while, for example, the `AuthorizeImplicitEndpointHandler` only implements
the `AuthorizeEndpointHandler` API.

You can find a complete list of handlers inside the [handler directory](). A short list is documented here:

* `github.com/ory-am/fosite/handler/core/explicit.AuthorizeExplicitEndpointHandler` implements the
  [Authorization Code Grant](https://tools.ietf.org/html/rfc6749#section-4.1)
* `github.com/ory-am/fosite/handler/core/implicit.AuthorizeImplicitEndpointHandler` implements the
  [Implicit Grant](https://tools.ietf.org/html/rfc6749#section-4.2)
* `github.com/ory-am/fosite/handler/core/token/owner.TokenROPasswordCredentialsEndpointHandler` implements the
  [Resource Owner Password Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.3)
* `github.com/ory-am/fosite/handler/core/token/client.TokenClientCredentialsEndpointHandler` implements the
  [Client Credentials Grant](https://tools.ietf.org/html/rfc6749#section-4.4)

### Replaceable storage

Fosite does not ship a storage implementation yet. To get fosite running, you need to implement `github.com/ory-am/fosite.Storage`.
Additionally, most of the token / authorize endpoint handlers require a store as well. It is probably smart to
implement all of those interfaces in one struct.

## Develop fosite

You need git and golang installed on your system.

```
go get github.com/ory-am/fosite/... -d
cd $GOPATH/src/ github.com/ory-am/fosite
git status
git remote add myfork <url-to-your-fork>
go test ./...
```

Simple, right? Now you are ready to go! Make sure to run `go test ./...` often, detecting problems with your code
rather sooner than later.

### Useful commands

**Create storage mocks**
```
mockgen -destination internal/storage.go github.com/ory-am/fosite Storage
mockgen -destination internal/core_client_storage.go github.com/ory-am/fosite/handler/core/client ClientCredentialsGrantStorage
mockgen -destination internal/core_explicit_storage.go github.com/ory-am/fosite/handler/core/explicit AuthorizeCodeGrantStorage
mockgen -destination internal/core_implicit_storage.go github.com/ory-am/fosite/handler/core/implicit ImplicitGrantStorage
mockgen -destination internal/core_owner_storage.go github.com/ory-am/fosite/handler/core/owner ResourceOwnerPasswordCredentialsGrantStorage
mockgen -destination internal/core_refresh_storage.go github.com/ory-am/fosite/handler/core/refresh RefreshTokenGrantStorage
```

**Create handler mocks**
```
mockgen -destination internal/authorize_handler.go github.com/ory-am/fosite AuthorizeEndpointHandler
mockgen -destination internal/token_handler.go github.com/ory-am/fosite TokenEndpointHandler
```

**Create stateful "context" mocks**
```
mockgen -destination internal/client.go github.com/ory-am/fosite/client Client
mockgen -destination internal/access_request.go github.com/ory-am/fosite AccessRequester
mockgen -destination internal/access_response.go github.com/ory-am/fosite AccessResponder
mockgen -destination internal/authorize_request.go github.com/ory-am/fosite AuthorizeRequester
mockgen -destination internal/authorize_response.go github.com/ory-am/fosite AuthorizeResponder
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