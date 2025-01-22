// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/hash.go github.com/ory/fosite Hasher
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/storage.go github.com/ory/fosite Storage
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/transactional.go github.com/ory/fosite/storage Transactional
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/oauth2_storage.go github.com/ory/fosite/handler/oauth2 CoreStorage
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/oauth2_strategy.go github.com/ory/fosite/handler/oauth2 CoreStrategy
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/authorize_code_storage.go github.com/ory/fosite/handler/oauth2 AuthorizeCodeStorage
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/device_code_storage.go github.com/ory/fosite/handler/rfc8628 DeviceCodeStorage
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/oauth2_auth_jwt_storage.go github.com/ory/fosite/handler/rfc7523 RFC7523KeyStorage
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/access_token_storage.go github.com/ory/fosite/handler/oauth2 AccessTokenStorage
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/refresh_token_strategy.go github.com/ory/fosite/handler/oauth2 RefreshTokenStorage
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/oauth2_client_storage.go github.com/ory/fosite/handler/oauth2 ClientCredentialsGrantStorage
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/oauth2_owner_storage.go github.com/ory/fosite/handler/oauth2 ResourceOwnerPasswordCredentialsGrantStorage
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/oauth2_revoke_storage.go github.com/ory/fosite/handler/oauth2 TokenRevocationStorage
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/openid_id_token_storage.go github.com/ory/fosite/handler/openid OpenIDConnectRequestStorage
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/access_token_strategy.go github.com/ory/fosite/handler/oauth2 AccessTokenStrategy
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/refresh_token_strategy.go github.com/ory/fosite/handler/oauth2 RefreshTokenStrategy
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/authorize_code_strategy.go github.com/ory/fosite/handler/oauth2 AuthorizeCodeStrategy
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/device_code_rate_limit_strategy.go github.com/ory/fosite/handler/rfc8628 DeviceRateLimitStrategy
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/id_token_strategy.go github.com/ory/fosite/handler/openid OpenIDConnectTokenStrategy
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/pkce_storage_strategy.go github.com/ory/fosite/handler/pkce PKCERequestStorage
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/authorize_handler.go github.com/ory/fosite AuthorizeEndpointHandler
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/revoke_handler.go github.com/ory/fosite RevocationHandler
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/token_handler.go github.com/ory/fosite TokenEndpointHandler
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/introspector.go github.com/ory/fosite TokenIntrospector
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/client.go github.com/ory/fosite Client
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/request.go github.com/ory/fosite Requester
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/access_request.go github.com/ory/fosite AccessRequester
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/access_response.go github.com/ory/fosite AccessResponder
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/authorize_request.go github.com/ory/fosite AuthorizeRequester
//go:generate go run github.com/golang/mock/mockgen -package internal -destination internal/authorize_response.go github.com/ory/fosite AuthorizeResponder
