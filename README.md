# ![Fosite](fosite.png)

Simple and extensible OAuth2 server-side helpers with enterprise security and zero suck.
This library implements [rfc6749](https://tools.ietf.org/html/rfc6749) and enforces countermeasures suggested in [rfc6819](https://tools.ietf.org/html/rfc6819).

[![Build Status](https://travis-ci.org/ory-am/fosite.svg?branch=master)](https://travis-ci.org/ory-am/fosite?branch=master)
[![Coverage Status](https://coveralls.io/repos/ory-am/fosite/badge.svg?branch=master&service=github)](https://coveralls.io/github/ory-am/fosite?branch=master)

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Motivation](#motivation)
- [Good to know](#good-to-know)
- [Security](#security)
  - [Encourage security by enforcing it!](#encourage-security-by-enforcing-it)
  - [Provide extensibility and interoperability](#provide-extensibility-and-interoperability)
  - [Tokens](#tokens)
- [Usage](#usage)
  - [Store](#store)
  - [Authorize Endpoint](#authorize-endpoint)
  - [OpenID Connect](#openid-connect)
  - [Token Endpoint](#token-endpoint)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Motivation

Why write another OAuth2 server side library for Go Lang?

Other libraries are perfect for a non-critical set ups, but [fail](https://github.com/RangelReale/osin/issues/107) to comply with enterprise security standards.
This is unfortunately not an issue exclusive to Go's eco system but to many other eco systems as well.

OpenID Connect on top of OAuth2? Not possible with popular OAuth2 libraries. Current libraries do not support capture
the extensibility of OAuth2 and instead bind you to a pattern-enforcing framework with almost no possibilities for extension.

Fosite was written because [Hydra](https://github.com/ory-am/hydra) required a more secure and extensible OAuth2 library
then the one it was using.

## Good to know

Fosite is in early development. We will use gopkg for releasing new versions of the API.
Be aware that "go get github.com/ory-am/fosite" will give you the master branch, which is and always will be *unstable*.
Once releases roll out, you will be able to fetch a specific fosite API version through gopkg.in.

## Security

Fosite has two commandments.

### Encourage security by enforcing it!

This is achieved with:
* **Secure Tokens:** Tokens are generated with a minimum entropy of 256 bit. You can use more, if you want.
* **No state, no token:** Without a random-looking state, *GET /oauth2/auth* will fail.
* **Opaque tokens:** Token generators should know nothing about the request or context.
* **Advanced Token Validation:** Tokens are layouted as `<key>.<signature>`. The following workflow requires an attacker
 to gain *(a)* access to the database *(b)* write permission in the persistent store, *(c)* get hold of the token encryption secret. A database leak
 or (exclusively) the knowledge of the token encrpytion secret are not enough to maliciously obtain or create a valid token. Tokens and credentials can
 however still be stolen by man-in-the-middle attacks, by malicious or vulnerable clients and other attack vectors.
 * Issuance
    1. The key is hashed using BCrypt (variable) and used as <signature>.
    2. The client is presented with `<key>.<signature>`.
    3. The signature is encrypted and stored in the database using AES (variable).
 * Validation
    1. The client presents `<key>.<signature>``.
    2. It is validated if <key> matches <signature> using BCrypt (variable).
    3. The signature is encrypted using AES (variable).
    4. The encrypted signature is looked up in the database, failing validation if no such row exists.
    5. They key is considered valid and is now subject for other validations, like audience, redirect or state matching.
* **Encrypt credentials at rest:** Credentials (tokens, passwords and secrets) are always be stored encrypted.
* **Implement peer reviewed IETF Standards:** Fosite implements [rfc6749](https://tools.ietf.org/html/rfc6749) and enforces countermeasures suggested in [rfc6819](https://tools.ietf.org/html/rfc6819).

### Provide extensibility and interoperability

... because OAuth2 is an extensible and flexible **framework**. Fosite let's you register new response types, new grant
types and new response key value pares. This is useful, if you want to provide OpenID Connect on top of your
OAuth2 stack. Or custom assertions, what ever you like and as long as it is secure. ;)

### Tokens

Tokens are formatted as `<key>.<signature>`. This is beneficial if you want to keep tokens encrypted at rest.
To validate a token in a OAuth2 grant, you could first check if the key matches the signature and then lookup the signature
in your persistent storage (e.g. MySQL). If your persistent storage is intruded (e.g. by SQL injection), an attacker would
only have access to the token signatures and would be, because he does not know the key, unable to use them for authorization.

A token generated by `generator.CryptoGenerator` looks like:

```
GUULhK6Od/7UAlnKvMau8APHSKXSRwm9aoOk56SHBns.JDJhJDEwJDdwVmpCQmJLYzM2VDg1VHJ5aEdVOE81NVdRSkt6bHBHR1QwOC9pbTNFWmpQRXliTWRPeDQy
```

## Usage

This section is WIP and we welcome discussions via PRs or in the issues.

### Store

### Authorize Endpoint

```go
var r *http.Request // we're assuming that we are inside a http.Handler
var rw http.ResponseWriter  // we're assuming that we are inside a http.Handler

var store fosite.Storage // needs to be implemented or by using some library
config := fosite.NewDefaultConfig()
oauth := fosite.NewOAuth(config)
authorizeRequest, err := oauth.NewAuthorizeRequest(r, store)
if err != nil {
    oauth.RedirectError(rw, error)
    // or, for example: oauth.WriteError(rw, error)
    return
}

// you have now access to authorizeRequest.Scope, ...Code ...ResponseTypes ...Scopes ...

// decide what to do based on scope and response type
// e.g: response, err = oauth.HandleAuthorizeRequest(authorizeRequest)

// set up a session
// session := oauth2.NewAuthorizeSession(123)
// session.SetExtra(extra interface{})

// persist that stuff in the database
// err = oauth2.PersistAuthorizeRequest(authorizeRequest, session) // sets e.g. session.Persistent = true

// finally, persist code in store and send response
// e.g: oauth2.WriteResponse(rw, response, session)
```

Because each component returns a different type, we can be (if safeguards are installed) quite sure, that the developer
implemented the work flow the right way:

1. `NewAuthorizeRequest(args...) *AuthorizeRequest`: Fetch authorize request information
2. do whatever you like
3. `HandleAuthorizeRequest(args...) *AuthorizeResponse`: Handle authorize request (check scopes and response types, hydrate response...)
4. do whatever you like
5. `oauth2.NewAuthorizeSession(*AuthorizeResponse) *AuthorizeSession`: A session
6. do whatever you like, e.g. `session.SetExtra(map[string]interface{"foo": "bar"})`
7. `oauth2.PersistAuthorizeRequest` persists the request in the database so the token endpoint can look up information
8. do whatever you like
9. `oauth2.WriteResponse(rw, response, session)` to write the response
10. done.

It is not clear yet how HandleAuthorizeRequest could be extensible. It might be possible to introduce an interface like AuthorizeStrategy
and implement different strategies like IDTokenStrategy, AuthorizeCodeStrategy, AccessTokenStrategy.
What could be tricky though is to define a good response / result model because the strategies be very different in execution logic and requirements.

### OpenID Connect

### Token Endpoint