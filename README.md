# fosite
Simple and extensible OAuth2 server-side helpers with enterprise security and zero suck. This library implements rfc6819 and rfc6749.

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

Fosite has three basic rules:
1. Hash credentials (secrets, tokens, codes) at rest.
2. Enforce security rather than encouraging it:
 * Tokens can not have less than 256 bit entropy.
 * No strong state parameter = no token.
 * Tokens are opaque.
3. Be as extensible as possible.