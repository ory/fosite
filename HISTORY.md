This is a list of breaking changes. As long as `1.0.0` is not released, breaking changes will be addressed as minor version
bumps (`0.1.0` -> `0.2.0`).

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