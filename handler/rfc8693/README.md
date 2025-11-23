# RFC 8693 - OAuth 2.0 Token Exchange

This package implements
[RFC 8693 - OAuth 2.0 Token Exchange](https://tools.ietf.org/html/rfc8693) for
Fosite.

Feedback welcome ! Harry Kodden, SURF harry.kodden - at - surf.nl

## Overview

OAuth 2.0 Token Exchange allows clients to exchange one token for another token.
This is useful for scenarios such as:

- **Token Translation**: Converting an external token (e.g., from another
  identity provider) into a local token
- **Token Impersonation**: Allowing a service to act on behalf of a user with
  reduced privileges
- **Token Delegation**: Delegating access to a downstream service with specific
  scopes
- **Cross-Domain Token Exchange**: Exchanging tokens between different domains
  or services

## Configuration

To enable RFC 8693 Token Exchange, you need to:

### 1. Enable Token Exchange in Configuration

```go
config := &fosite.Config{
    TokenExchangeEnabled: true,
    TokenExchangeTokenTypes: []string{
        "urn:ietf:params:oauth:token-type:access_token",
        "urn:ietf:params:oauth:token-type:refresh_token",
        "urn:ietf:params:oauth:token-type:id_token",
    },
}
```

### 2. Register the Handler

```go
import (
    "github.com/ory/fosite/compose"
    "github.com/ory/fosite/handler/rfc8693"
)

// Setup the staregies for Access Token & Refresh Tokens
AccessTokenStrategy = compose.NewOAuth2HMACStrategy(config)
RefreshTokenStrategy = compose.NewOAuth2HMACStrategy(config)

// Using the compose package
oauth2Provider := compose.Compose(
    config,
    storage,
    strategy,
    // ... other factories
    compose.RFC8693TokenExchangeFactory,
)


// Or manually
handler := &rfc8693.Handler{
    Config:               config,
    AccessTokenStorage:   storage,
    RefreshTokenStorage:  storage,
    AccessTokenStrategy:  strategy,
    RefreshTokenStrategy: strategy,
    HandleHelper: &oauth2.HandleHelper{
        AccessTokenStrategy: strategy,
        AccessTokenStorage:  storage,
        Config:              config,
    },
}
oauth2Provider.TokenEndpointHandlers.Append(handler)
```

## Usage

### Client Authentication

The RFC 8693 Token Exchange endpoint supports both HTTP Basic Authentication and
form-based client authentication:

**HTTP Basic Authentication (Recommended):**

```http
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=...
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
```

**Form-Based Authentication:**

```http
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=...
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&client_id=s6BhdRkqt3
&client_secret=gX1fBat3bV
```

### Basic Token Exchange Request

```http
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
```

### Token Exchange with Form-Based Client Authentication

```http
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&client_id=s6BhdRkqt3
&client_secret=gX1fBat3bV
```

### Token Exchange with Scope Restriction

```http
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&scope=read write:limited
&audience=https://api.example.com
```

### Token Exchange with Actor (Delegation)

```http
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&actor_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
&actor_token_type=urn:ietf:params:oauth:token-type:access_token
```

### Successful Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

## Token Types

The following token types are supported by default:

- `urn:ietf:params:oauth:token-type:access_token` - OAuth 2.0 access tokens
- `urn:ietf:params:oauth:token-type:refresh_token` - OAuth 2.0 refresh tokens
- `urn:ietf:params:oauth:token-type:id_token` - OpenID Connect ID tokens
- `urn:ietf:params:oauth:token-type:jwt` - Generic JWT tokens

You can configure which token types are supported via the
`TokenExchangeTokenTypes` configuration option.

## Parameters

### Required Parameters

- `grant_type`: Must be `urn:ietf:params:oauth:grant-type:token-exchange`
- `subject_token`: The token to be exchanged
- `subject_token_type`: The type of the subject token

### Optional Parameters

- `requested_token_type`: The type of token being requested (defaults to
  access_token)
- `audience`: The intended audience for the issued token
- `scope`: The requested scope (must be a subset of the subject token's scope)
- `resource`: The physical or logical location of the target resource
- `actor_token`: Token representing the party authorized to use the issued token
- `actor_token_type`: The type of the actor token

## Error Responses

Token exchange can return the following error types:

- `invalid_request` - Missing or invalid required parameters
- `invalid_client` - Client authentication failed
- `invalid_grant` - Subject token is invalid, expired, or revoked
- `invalid_scope` - Requested scope exceeds subject token scope
- `invalid_target` - Requested audience is not allowed
- `unsupported_grant_type` - Token exchange is disabled

## Security Considerations

1. **Client Authentication**: RFC 8693 supports both HTTP Basic Authentication
   and form-based client authentication. HTTP Basic Authentication is
   recommended as it keeps credentials out of the request body and logs.
2. **Token Validation**: Always properly validate subject and actor tokens
3. **Scope Restriction**: Ensure issued tokens have equal or reduced privileges
4. **Audience Validation**: Verify that the client is authorized for the
   requested audience
5. **Rate Limiting**: Implement rate limiting to prevent abuse
6. **Audit Logging**: Log all token exchange operations for security monitoring
7. **Token Lifetime**: Use appropriate token lifespans for issued tokens

## Example Implementation

See `example_storage.go` for a basic implementation that shows how to integrate
with existing Fosite storage patterns.
