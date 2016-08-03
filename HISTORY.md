This is a list of breaking changes. As long as `1.0.0` is not released, breaking changes will be addressed as minor version
bumps (`0.1.0` -> `0.2.0`).

## 0.2.0

Breaking changes:

* Token validation refactored: `ValidateRequestAuthorization` is now `Validate` and does not require a http request
but instead a token and a token hint. A token can be anything, including authorization codes, refresh tokens,
id tokens, ...
* Remove mandatory scope: The mandatory scope (`fosite`) has been removed as it has proven impractical.

## 0.1.0

Initial release