#!/bin/bash

mockgen -package internal -destination internal/hash.go github.com/ory/fosite Hasher
mockgen -package internal -destination internal/storage.go github.com/ory/fosite Storage
mockgen -package internal -destination internal/client_manager.go github.com/ory/fosite ClientManager
mockgen -package internal -destination internal/transactional.go github.com/ory/fosite Transactional
mockgen -package internal -destination internal/oauth2_storage.go github.com/ory/fosite/handler/oauth2 CoreStorage
mockgen -package internal -destination internal/oauth2_strategy.go github.com/ory/fosite/handler/oauth2 CoreStrategy
mockgen -package internal -destination internal/authorize_code_storage.go github.com/ory/fosite/handler/oauth2 AuthorizeCodeStorage
mockgen -package internal -destination internal/rfc8628_core_storage.go github.com/ory/fosite/handler/rfc8628 Storage -mock-names Storage=MockRFC8628Storage
mockgen -package internal -destination internal/rfc8628_device_auth_storage.go github.com/ory/fosite/handler/rfc8628 DeviceAuthStorage
mockgen -package internal -destination internal/rfc8628_device_auth_storage_provider.go github.com/ory/fosite/handler/rfc8628 DeviceAuthStorageProvider
mockgen -package internal -destination internal/oauth2_auth_jwt_storage.go github.com/ory/fosite/handler/rfc7523 RFC7523KeyStorage
mockgen -package internal -destination internal/access_token_storage.go github.com/ory/fosite/handler/oauth2 AccessTokenStorage
mockgen -package internal -destination internal/refresh_token_storage.go github.com/ory/fosite/handler/oauth2 RefreshTokenStorage
mockgen -package internal -destination internal/oauth2_client_storage.go github.com/ory/fosite/handler/oauth2 ClientCredentialsGrantStorage
mockgen -package internal -destination internal/oauth2_owner_storage.go github.com/ory/fosite/handler/oauth2 ResourceOwnerPasswordCredentialsGrantStorage
mockgen -package internal -destination internal/oauth2_revoke_storage.go github.com/ory/fosite/handler/oauth2 TokenRevocationStorage
mockgen -package internal -destination internal/access_token_strategy.go github.com/ory/fosite/handler/oauth2 AccessTokenStrategy
mockgen -package internal -destination internal/refresh_token_strategy.go github.com/ory/fosite/handler/oauth2 RefreshTokenStrategy
mockgen -package internal -destination internal/authorize_code_strategy.go github.com/ory/fosite/handler/oauth2 AuthorizeCodeStrategy
mockgen -package internal -destination internal/rfc8628_code_strategy.go github.com/ory/fosite/handler/rfc8628 RFC8628CodeStrategy
mockgen -package internal -destination internal/device_code_rate_limit_strategy.go github.com/ory/fosite/handler/rfc8628 DeviceRateLimitStrategy
mockgen -package internal -destination internal/id_token_strategy.go github.com/ory/fosite/handler/openid OpenIDConnectTokenStrategy
mockgen -package internal -destination internal/authorize_handler.go github.com/ory/fosite AuthorizeEndpointHandler
mockgen -package internal -destination internal/revoke_handler.go github.com/ory/fosite RevocationHandler
mockgen -package internal -destination internal/token_handler.go github.com/ory/fosite TokenEndpointHandler
mockgen -package internal -destination internal/introspector.go github.com/ory/fosite TokenIntrospector
mockgen -package internal -destination internal/client.go github.com/ory/fosite Client
mockgen -package internal -destination internal/request.go github.com/ory/fosite Requester
mockgen -package internal -destination internal/access_request.go github.com/ory/fosite AccessRequester
mockgen -package internal -destination internal/access_response.go github.com/ory/fosite AccessResponder
mockgen -package internal -destination internal/authorize_request.go github.com/ory/fosite AuthorizeRequester
mockgen -package internal -destination internal/authorize_response.go github.com/ory/fosite AuthorizeResponder
mockgen -package internal -destination internal/par_storage.go github.com/ory/fosite PARStorage
mockgen -package internal -destination internal/par_storage_provider.go github.com/ory/fosite PARStorageProvider
mockgen -package internal -destination internal/access_token_storage_provider.go github.com/ory/fosite/handler/oauth2 AccessTokenStorageProvider
mockgen -package internal -destination internal/authorize_code_storage_provider.go github.com/ory/fosite/handler/oauth2 AuthorizeCodeStorageProvider
mockgen -package internal -destination internal/refresh_token_storage_provider.go github.com/ory/fosite/handler/oauth2 RefreshTokenStorageProvider
mockgen -package internal -destination internal/token_revocation_storage_provider.go github.com/ory/fosite/handler/oauth2 TokenRevocationStorageProvider
mockgen -package internal -destination internal/oidc_request_storage.go github.com/ory/fosite/handler/openid OIDCRequestStorage
mockgen -package internal -destination internal/oidc_request_storage_provider.go github.com/ory/fosite/handler/openid OIDCRequestStorageProvider
mockgen -package internal -destination internal/pkce_request_storage.go github.com/ory/fosite/handler/pkce PKCERequestStorage
mockgen -package internal -destination internal/pkce_request_storage_provider.go github.com/ory/fosite/handler/pkce PKCERequestStorageProvider

goimports -w internal/
