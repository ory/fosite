This is a list of breaking changes. As long as `1.0.0` is not released, breaking changes will be addressed as minor version
bumps (`0.1.0` -> `0.2.0`).

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [0.15.0](#0150)
- [0.14.0](#0140)
- [0.13.0](#0130)
  - [Breaking changes](#breaking-changes)
- [0.12.0](#0120)
  - [Breaking changes](#breaking-changes-1)
    - [Improved cryptographic methods](#improved-cryptographic-methods)
- [0.11.0](#0110)
  - [Non-breaking changes](#non-breaking-changes)
    - [Storage adapter](#storage-adapter)
    - [Reducing use of gomock](#reducing-use-of-gomock)
  - [Breaking Changes](#breaking-changes)
    - [`fosite/handler/oauth2.AuthorizeCodeGrantStorage` was removed](#fositehandleroauth2authorizecodegrantstorage-was-removed)
    - [`fosite/handler/oauth2.RefreshTokenGrantStorage` was removed](#fositehandleroauth2refreshtokengrantstorage-was-removed)
    - [`fosite/handler/oauth2.AuthorizeCodeGrantStorage` was removed](#fositehandleroauth2authorizecodegrantstorage-was-removed-1)
    - [WildcardScopeStrategy](#wildcardscopestrategy)
    - [Refresh tokens and authorize codes are no longer JWTs](#refresh-tokens-and-authorize-codes-are-no-longer-jwts)
    - [Delete access tokens when persisting refresh session](#delete-access-tokens-when-persisting-refresh-session)
- [0.10.0](#0100)
- [0.9.0](#090)
- [0.8.0](#080)
  - [Breaking changes](#breaking-changes-2)
    - [`ClientManager`](#clientmanager)
    - [`OAuth2Provider`](#oauth2provider)
- [0.7.0](#070)
- [0.6.0](#060)
- [0.5.0](#050)
- [0.4.0](#040)
- [0.3.0](#030)
- [0.2.0](#020)
- [0.1.0](#010)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## 0.16.0

This patch introduces `SendDebugMessagesToClients` to the Fosite struct which enables/disables sending debug information to
clients. Debug information may contain sensitive information as it forwards error messages from, for example, storage
implementations. For this reason, `RevealDebugPayloads` defaults to false. Keep in mind that the information may be
very helpful when specific OAuth 2.0 requests fail and we generally recommend displaying debug information.

Additionally, error keys for JSON changed which caused a new minor version, speicifically
[`statusCode` was changed to `status_code`](https://github.com/ory/fosite/pull/242/files#diff-dd25e0e0a594c3f3592c1c717039b85eR221).


## 0.15.0

This release focuses on improving compatibility with OpenID Connect Certification and better error context.

* Error handling is improved by explicitly adding debug information (e.g. "Token invalid because it was not found
in the database") to the error object. Previously, the original error was prepended which caused weird formatting issues.
* Allows client credentials in POST body at the `/oauth2/token` endpoint. Please note that this method is not recommended
to be used, unless the client making the request is unable to use HTTP Basic Authorization.
* Allows public clients (without secret) to access the `/oauth2/token` endpoint which was previously only possible by adding an arbitrary
secret.

This release has no breaking changes to the external API but due to the nature of the changes, it is released
as a new major version.

## 0.14.0

Improves error contexts. A breaking code changes to the public API was reverted with 0.14.1.

## 0.13.0

### Breaking changes

`glide` was replaced with `dep`.

## 0.12.0

### Breaking changes

#### Improved cryptographic methods

* The minimum required secret length used to generate signatures of access tokens has increased from 16 to 32 byte.
* The algorithm used to generate access tokens using the HMAC-SHA strategy has changed from HMAC-SHA256 to HMAC-SHA512.

## 0.11.0

### Non-breaking changes

#### Storage adapter

To simplify the storage adapter logic, and also reduce the likelihoods of bugs within the storage adapter, the
interface was greatly simplified. Specifically, these two methods have been removed:

* `PersistRefreshTokenGrantSession(ctx context.Context, requestRefreshSignature, accessSignature, refreshSignature string, request fosite.Requester) error`
* `PersistAuthorizeCodeGrantSession(ctx context.Context, authorizeCode, accessSignature, refreshSignature string, request fosite.Requester) error`

For this change, you don't need to do anything. You can however simply delete those two methods from your store.

#### Reducing use of gomock

In the long term, fosite should remove all gomocks and instead test against the internal implementations. This
will increase iterations per line during tests and reduce annoying mock updates.

### Breaking Changes

#### `fosite/handler/oauth2.AuthorizeCodeGrantStorage` was removed

`AuthorizeCodeGrantStorage` was used specifically in the composer. Refactor references to `AuthorizeCodeGrantStorage` with `CoreStorage`.

#### `fosite/handler/oauth2.RefreshTokenGrantStorage` was removed

`RefreshTokenGrantStorage` was used specifically in the composer. Refactor references to `RefreshTokenGrantStorage` with `CoreStorage`.

#### `fosite/handler/oauth2.AuthorizeCodeGrantStorage` was removed

`AuthorizeCodeGrantStorage` was used specifically in the composer. Refactor references to `AuthorizeCodeGrantStorage` with `CoreStorage`.

#### WildcardScopeStrategy

A new [scope strategy](https://github.com/ory/fosite/pull/187) was introduced called `WildcardScopeStrategy`. This strategy is now the default when using
the composer. To set the HierarchicScopeStrategy strategy, do:

```
import "github.com/ory/fosite/compose"

var config = &compose.Config{
    ScopeStrategy: fosite.HierarchicScopeStrategy,
}
```

#### Refresh tokens and authorize codes are no longer JWTs

Using JWTs for refresh tokens and authorize codes did not make sense:

1. Refresh tokens are long-living credentials, JWTs require an expiry date.
2. Refresh tokens are never validated client-side, only server-side. Thus access to the store is available.
3. Authorize codes are never validated client-side, only server-side.

Also, one compose method changed due to this:

```go
package compose

// ..

- func NewOAuth2JWTStrategy(key *rsa.PrivateKey) *oauth2.RS256JWTStrategy
+ func NewOAuth2JWTStrategy(key *rsa.PrivateKey, strategy *oauth2.HMACSHAStrategy) *oauth2.RS256JWTStrategy
```

#### Delete access tokens when persisting refresh session

Please delete access tokens in your store when you persist a refresh session. This increases security. Here
is an example of how to do that using only existing methods:

```go
func (s *MemoryStore) PersistRefreshTokenGrantSession(ctx context.Context, originalRefreshSignature, accessSignature, refreshSignature string, request fosite.Requester) error {
	if ts, err := s.GetRefreshTokenSession(ctx, originalRefreshSignature, nil); err != nil {
		return err
	} else if err := s.RevokeAccessToken(ctx, ts.GetID()); err != nil {
		return err
	} else if err := s.RevokeRefreshToken(ctx, ts.GetID()); err != nil {
 		return err
 	} else if err := s.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
 		return err
 	} else if err := s.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
 		return err
 	}

 	return nil
}
```

## 0.10.0

It is no longer possible to introspect authorize codes, and passing scopes to the introspector now also checks
refresh token scopes.

## 0.9.0

This patch adds the ability to pass a custom hasher to `compose.Compose`, which is a breaking change. You can pass nil for the fosite default hasher:

```
package compose

-func Compose(config *Config, storage interface{}, strategy interface{}, factories ...Factory) fosite.OAuth2Provider {
+func Compose(config *Config, storage interface{}, strategy interface{}, hasher fosite.Hasher, factories ...Factory) fosite.OAuth2Provider {
```

## 0.8.0

This patch addresses some inconsistencies in the public interfaces. Also
remaining references to the old repository location at `ory-am/fosite` 
where updated to `ory/fosite`.

### Breaking changes

#### `ClientManager`

The [`ClientManager`](https://github.com/ory/fosite/blob/master/client_manager.go) interface
changed, as a context parameter was added:

```go
type ClientManager interface {
	// GetClient loads the client by its ID or returns an error
  	// if the client does not exist or another error occurred.
-	GetClient(id string) (Client, error)
+	GetClient(ctx context.Context, id string) (Client, error)
}
```

#### `OAuth2Provider`

The [OAuth2Provider](https://github.com/ory/fosite/blob/master/oauth2.go) interface changed,
as the need for passing down `*http.Request` was removed. This is justifiable
because `NewAuthorizeRequest` and `NewAccessRequest` already contain `*http.Request`.

The public api of those two methods changed:

```go
-	NewAuthorizeResponse(ctx context.Context, req *http.Request, requester AuthorizeRequester, session Session) (AuthorizeResponder, error)
+	NewAuthorizeResponse(ctx context.Context, requester AuthorizeRequester, session Session) (AuthorizeResponder, error)


-	NewAccessResponse(ctx context.Context, req *http.Request, requester AccessRequester) (AccessResponder, error)
+	NewAccessResponse(ctx context.Context, requester AccessRequester) (AccessResponder, error)
```

## 0.7.0

Breaking changes:

* Replaced `"golang.org/x/net/context"` with `"context"`.
* Move the repo from `github.com/ory-am/fosite` to `github.com/ory/fosite`

## 0.6.0

A bug related to refresh tokens was found. To mitigate it, a `Clone()` method has been introduced to the `fosite.Session` interface.
If you use a custom session object, this will be a breaking change. Fosite's default sessions have been upgraded and no additional
work should be required. If you use your own session struct, we encourage using package `gob/encoding` to deep-copy it in `Clone()`.

## 0.5.0

Breaking changes:

* `compose.OpenIDConnectExplicit` is now `compose.OpenIDConnectExplicitFactory`
* `compose.OpenIDConnectImplicit` is now `compose.OpenIDConnectImplicitFactory`
* `compose.OpenIDConnectHybrid` is now `compose.OpenIDConnectHybridFactory`
* The token introspection handler is no longer added automatically by `compose.OAuth2*`. Add `compose.OAuth2TokenIntrospectionFactory`
to your composer if you need token introspection.
* Session refactor:
  * The HMACSessionContainer was removed and replaced by `fosite.Session` / `fosite.DefaultSession`. All sessions
  must now implement this signature. The new session interface allows for better expiration time handling.
  * The OpenID `DefaultSession` signature changed as well, it is now implementing the `fosite.Session` interface

## 0.4.0

Breaking changes:

* `./fosite-example` is now a separate repository: https://github.com/ory-am/fosite-example
* `github.com/ory-am/fosite/fosite-example/pkg.Store` is now `github.com/ory-am/fosite/storage.MemoryStore`
* `fosite.Client` has now a new method called `IsPublic()` which can be used to identify public clients who do not own a client secret
* All grant types except the client_credentials grant now allow public clients. public clients are usually mobile apps and single page apps.
* `TokenValidator` is now `TokenIntrospector`, `TokenValidationHandlers` is now `TokenIntrospectionHandlers`.
* `TokenValidator.ValidateToken` is now `TokenIntrospector.IntrospectToken`
* `fosite.OAuth2Provider.NewIntrospectionRequest()` has been added
* `fosite.OAuth2Provider.WriteIntrospectionError()` has been added
* `fosite.OAuth2Provider.WriteIntrospectionResponse()` has been added

## 0.3.0

* Updated jwt-go from 2.7.0 to 3.0.0

## 0.2.0

Breaking changes:

* Token validation refactored: `ValidateRequestAuthorization` is now `Validate` and does not require a http request
but instead a token and a token hint. A token can be anything, including authorization codes, refresh tokens,
id tokens, ...
* Remove mandatory scope: The mandatory scope (`fosite`) has been removed as it has proven impractical.
* Allowed OAuth2 Client scopes are now being set with `scope` instead of `granted_scopes` when using the DefaultClient.
* There is now a scope matching strategy that can be replaced.
* OAuth2 Client scopes are now checked on every grant type.
* Handler subpackages such as `core/client` or `oidc/explicit` have been merged and moved one level up
* `handler/oidc` is now `handler/openid`
* `handler/core` is now `handler/oauth2`

## 0.1.0

Initial release
