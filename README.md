# ![Fosite security first OAuth2 framework](fosite.png)

**The security first OAuth2 framework for [Google's Go Language](https://golang.org).**
Built simple, powerful and extensible. This library implements peer-reviewed [IETF RFC6749](https://tools.ietf.org/html/rfc6749),
counterfeits weaknesses covered in peer-reviewed [IETF RFC6819](https://tools.ietf.org/html/rfc6819) and countermeasures various database
attack scenarios, keeping your application safe when that hacker penetrates and leaks your database.

If you are here to contribute, feel free to check [this Pull Request](https://github.com/ory-am/fosite/pull/1).

[![Build Status](https://travis-ci.org/ory-am/fosite.svg?branch=master)](https://travis-ci.org/ory-am/fosite?branch=master)
[![Coverage Status](https://coveralls.io/repos/ory-am/fosite/badge.svg?branch=master&service=github)](https://coveralls.io/github/ory-am/fosite?branch=master)

Fosite is in active development. We will use gopkg for releasing new versions of the API.
Be aware that "go get github.com/ory-am/fosite" will give you the master branch, which is and always will be *nightly*.
Once releases roll out, you will be able to fetch a specific fosite API version through gopkg.in.

These Standards have been reviewed during the development of Fosite:
* [OAuth 2.0 Multiple Response Type Encoding Practices](http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
* [OpenID Connect Core 1.0](http://openid.net/specs/openid-connect-core-1_0.html)
* [The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
* [OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819)

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Motivation](#motivation)
- [A word on quality](#a-word-on-quality)
- [A word on security](#a-word-on-security)
- [Security](#security)
  - [Encourage security by enforcing it](#encourage-security-by-enforcing-it)
    - [Secure Tokens](#secure-tokens)
    - [No state, no token](#no-state-no-token)
    - [Opaque tokens](#opaque-tokens)
    - [Advanced Token Validation](#advanced-token-validation)
    - [Encrypt credentials at rest](#encrypt-credentials-at-rest)
    - [Implement peer reviewed IETF Standards](#implement-peer-reviewed-ietf-standards)
  - [Provide extensibility and interoperability](#provide-extensibility-and-interoperability)
- [Usage](#usage)
  - [Authorize Endpoint](#authorize-endpoint)
  - [Token Endpoint](#token-endpoint)
  - [Extensible handlers](#extensible-handlers)
- [Hall of Fame](#hall-of-fame)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Motivation

Why write another OAuth2 server side library for Go Lang?

Other libraries are perfect for a non-critical set ups, but [fail](https://github.com/RangelReale/osin/issues/107)
to comply with advanced security requirements. Additionally, the frameworks we analyzed did not support extension
of the OAuth2 protocol easily. But OAuth2 is an extensible framework. Your OAuth2 should as well.
This is unfortunately not an issue exclusive to Go's eco system but to many others as well.

Fosite was written because [Hydra](https://github.com/ory-am/hydra) required a more secure and extensible OAuth2 library
then the one it was using. We quickly realized, that OAuth2 implementations out there are *not secure* nor *extensible,
so we decided to write one *that is*.

## A word on quality

We tried to set up as many tests as possible and test for as many cases covered in the RFCs as possible. But we are only
human. Please, feel free to add tests for the various cases defined in the OAuth2 RFCs 6749 and 6819.

**Everyone** writing an RFC conform test that breaks with the current implementation, will receive a place in the
[Hall of Fame](#hall-of-fame)!

## A word on security

Please be aware that Fosite only secures your server side security. You still need to secure your apps and clients, keep
your tokens safe, prevent CSRF attacks and much more. If you need any help or advice feel free to contact our security
staff through [our website](https://ory.am/)!

## Security first or encouraging security by enforcing it

We have given [OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819#section-5.1.5.3)
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

Not implemented yet:
* [Use of Asymmetric Cryptography](https://tools.ietf.org/html/rfc6819#section-5.1.4.1.5) - enigma should use asymmetric
  cryptography per default instead of HMAC-SHA (but support both).

Sections below [Section 5](https://tools.ietf.org/html/rfc6819#section-5)
that are not covered in the list above should be reviewed by you. If you think that a specific section should be something
that is covered in Fosite, feel free to create an [issue](https://github.com/ory-am/fosite/issues).

#### No state, no token

Without a random-looking state, *GET /oauth2/auth* will fail.

#### Opaque tokens

Token generators should know nothing about the request or context.

#### Advanced Token Validation

Tokens are layouted as `<key>.<signature>` where `<signature>` is created using HMAC-SHA256, a global secret
and the client's secret. Read more about this workflow in the [proposal](https://github.com/ory-am/fosite/issues/11).

A created token looks like:
```
/tgBeUhWlAT8tM8Bhmnx+Amf8rOYOUhrDi3pGzmjP7c=.BiV/Yhma+5moTP46anxMT6cWW8gz5R5vpC9RbpwSDdM=
```

#### Encrypt credentials at rest

Credentials (token signatures, passwords and secrets) are always encrypted at rest.

#### Implement peer reviewed IETF Standards

Fosite implements [rfc6749](https://tools.ietf.org/html/rfc6749) and enforces countermeasures suggested in [rfc6819](https://tools.ietf.org/html/rfc6819).

### Provide extensibility and interoperability

... because OAuth2 is an extensible and flexible **framework**. Fosite let's you register new response types, new grant
types and new response key value pares. This is useful, if you want to provide OpenID Connect on top of your
OAuth2 stack. Or custom assertions, what ever you like and as long as it is secure. ;)

## Usage

This section is WIP and we welcome discussions via PRs or in the issues.

### Installation

Obviously, you will need [Go](https://golang.org) installed on your machine and it is required that you have set up your
GOPATH environment variable.

Fosite is being shipped through gopkg.in so new updates don't break your code.

```
go get gopkg.in/ory-am/fosite.v{X}/...
```

To see a full list of available versions check the [tags](https://github.com/ory-am/fosite/tags) page. If you want
to use api version 2 for example (version 2 does not exist yet), do:

```
go get gopkg.in/ory-am/fosite.v2/...
```

To use the unstable master branch, which is only recommended for testing purposes, do:

```
go get gopkg.in/ory-am/fosite.v0/...
```

### Authorize Endpoint

```go
package main

import(
    "github.com/ory-am/fosite"
    "github.com/ory-am/fosite/service"
	"golang.org/x/net/context"
)


var store = fosite.NewPostgreSQLStore()
var oauth2 = service.NewDefaultOAuth2(store)

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
```

### Token Endpoint

draft

```go
func handleToken(rw http.ResponseWriter, req *http.Request) {
    var mySessionData = struct {
        User string
        UsingIdentityProvider string
        Foo string
    }

    accessRequest, err := oauth2.NewAccessRequest(ctx, r, &mySessionData)
    if err != nil {
       oauth2.WriteAccessError(rw, req, err)
       return
    }

    response, err := oauth2.NewAccessResponse(ctx, accessRequest, r, &mySessionData)
    if err != nil {
       oauth2.WriteAccessError(rw, req, err)
       return
    }

    oauth2.WriteAccessResponse(rw, accessRequest, response)
}
```

### Extensible handlers

You can replace Fosite's inner workings, for example response type (/auth endpoint) handlers or grant type
(/token endpoint) handlers.

Let's take the code handler. He is responsible for handling the
[authorize_code workflow](https://aaronparecki.com/articles/2012/07/29/1/oauth2-simplified#web-server-apps).
If you want to enable him, you could do it like this:

```go
codeHandler := &code.CodeAuthorizeEndpointHandler{
	Generator: &enigma.HMACSHAEnigma{GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows")},
	Store:     myCodeStore, // Needs to implement CodeResponseTypeStorage
}
oauth2 := &Fosite{
	AuthorizeEndpointHandlers: []AuthorizeEndpointHandler{
		codeHandler,
	},
}
```

Easy, right? You can add or remove any handler you wish like this, even custom ones and extend OAuth2 by, for example, OpenID
Connect.

The token endpoint is still in the making so stay tuned on how to run custom token endpoint handlers.

## Develop fosite

This section is work in progress.

### Useful commands

**Create storage mocks**
```
mockgen -destination internal/storage.go github.com/ory-am/fosite Storage
mockgen -destination internal/authorize_storage.go github.com/ory-am/fosite/handler/authorize AuthorizeStorage
mockgen -destination internal/token_storage.go github.com/ory-am/fosite/handler/token TokenStorage
```

**Create handler mocks**
```
mockgen -destination internal/authorize_handler.go github.com/ory-am/fosite AuthorizeEndpointHandler
mockgen -destination internal/token_handler.go github.com/ory-am/fosite TokenEndpointHandler
```

**Create stateful "context" mocks**
```
mockgen -destination internal/access_request.go github.com/ory-am/fosite AccessRequester
mockgen -destination internal/access__response.go github.com/ory-am/fosite AccessResponder
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