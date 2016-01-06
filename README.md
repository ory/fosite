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
  - [Store](#store)
  - [Authorize Endpoint](#authorize-endpoint)
  - [Token Endpoint](#token-endpoint)
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

## Security

Fosite has two commandments!

### Encourage security by enforcing it

#### Secure Tokens

Tokens are generated with a minimum entropy of 256 bit. You can use more, if you want.

#### No state, no token

Without a random-looking state, *GET /oauth2/auth* will fail.

#### Opaque tokens

Token generators should know nothing about the request or context.

#### Advanced Token Validation

Tokens are layouted as `<key>.<signature>`. The following workflow requires an attacker to gain

a. access to the database
b. write permission in the persistent store,
c. get hold of the token encryption secret.

A database leak or (exclusively) the knowledge of the token encrpytion secret are not enough to maliciously obtain or create a valid token. Tokens and credentials can
however still be stolen by man-in-the-middle attacks, by malicious or vulnerable clients and other attack vectors.

**Issuance**

1. The key is hashed using BCrypt (variable) and used as `<signature>`.
2. The client is presented and entrusted with `<key>.<signature>` which can act for example as an access token or an authorize code.
3. The signature is encrypted and stored in the database using AES (variable).

**Validation**

1. The client presents `<key>.<signature>`.
2. It is validated if <key> matches <signature> using BCrypt (variable).
3. The signature is encrypted using AES (variable).
4. The encrypted signature is looked up in the database, failing validation if no such row exists.
5. They key is considered valid and is now subject for other validations, like audience, redirect or state matching.

A token generated by `generator.CryptoGenerator` looks like:

```
GUULhK6Od/7UAlnKvMau8APHSKXSRwm9aoOk56SHBns.JDJhJDEwJDdwVmpCQmJLYzM2VDg1VHJ5aEdVOE81NVdRSkt6bHBHR1QwOC9pbTNFWmpQRXliTWRPeDQy
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

### Store

To use fosite, you need to implement `fosite.Storage`. Example implementations (e.g. postgres) of `fosite.Storage`
will be added in the close future.

### Authorize Endpoint

```go
package main

import(
    "github.com/ory-am/fosite"
    "github.com/ory-am/fosite/session"
    "github.com/ory-am/fosite/storage"
	"golang.org/x/net/context"
)

// Let's assume that we're in a http handler
func handleAuth(rw http.ResponseWriter, req *http.Request) {
    store := fosite.NewPostgreSQLStore()
    oauth2 := fosite.NewDefaultOAuth2(store)
    ctx := context.Background()

    // Let's create an AuthorizeRequest object!
    // It will analyze the request and extract important information like scopes, response type and others.
    authorizeRequest, err := oauth2.NewAuthorizeRequest(ctx, r)
    if err != nil {
       oauth2.WriteAuthorizeError(rw, req, err)
       return
    }

    // you have now access to authorizeRequest, Code ResponseTypes, Scopes ...
    // and can show the user agent a login or consent page.

    // it would also be possible to redirect the user to an identity provider (google, microsoft live, ...) here
    // and do fancy stuff like OpenID Connect amongst others

    // Once you have confirmed the users identity and consent that he indeed wants to give app XYZ authorization,
    // you will use the user's id to create an authorize session
    user := "12345"

    // NewAuthorizeSessionSQL uses gob.encode to safely store data set with SetExtra
    session := fosite.NewAuthorizeSessionSQL(authorizeRequest, user)

    // You can store additional metadata, for example:
    session.SetExtra(&struct{
        UserEmail string
        LastSeen time.Time
        UsingIdentityProvider string
    }{
         UserEmail: "foo@bar",
         LastSeen: new Date(),
         UsingIdentityProvider: "google",
    })


    // Now is the time to handle the response types
    // You can use a custom list of response type handlers by setting
    // oauth2.ResponseTypeHandlers = []fosite.ResponseTypeHandler{}
    response, err := oauth2.HandleResponseTypes(ctx, authorizeRequest, r)
    if err != nil {
       oauth2.WriteAuthorizeError(rw, req, err)
       return
    }

    // The next step is going to persist the session in the database for later use and redirect the
    // user agent back to the application demanding access.
    if err = oauth2.FinishAuthorizeRequest(rw, ar, response, session); err != nil {
        oauth2.WriteAuthorizeError(rw, req, err)
        return
    }

    // Done! The client should now have a valid authorize code!
}
```

### Token Endpoint

## Hall of Fame

This place is reserved for the fearless bug hunters, reviewers and contributors.

Find out more about the [author](https://aeneas.io/) of Fosite and Hydra, and the
[Ory Company](https://ory.am/).