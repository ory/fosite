This is a list of breaking changes. As long as `1.0.0` is not released, breaking changes will be addressed as minor version
bumps (`0.1.0` -> `0.2.0`).

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [0.9.0](#090)
- [0.8.0](#080)
  - [Breaking changes](#breaking-changes)
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
