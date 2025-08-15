# RFC 8693 Token Exchange Examples

This directory contains examples showing how to use the RFC 8693 Token Exchange
implementation in Fosite.

## Files

- `example_integration.go` - Complete working example showing how to set up an
  OAuth2 server with RFC 8693 Token Exchange support

## Running the Example

```bash
go run examples/rfc8693/example_integration.go
```

This will start an OAuth2 server on port 8080 with token exchange capability
enabled.

## Example Usage

Once the server is running, you can test token exchange with:

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=<existing_access_token>" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "scope=read" \
  -d "client_id=test-client" \
  -d "client_secret=test-secret"
```

Note: This example uses simplified token validation for demonstration purposes.
In production, you should implement proper token signature validation.

Note: This example uses the form based authentication of the requesting client,
it is recommended to use the basic authentication instead.
