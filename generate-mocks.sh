#!/bin/bash

mockgen -package internal -destination internal/storage.go github.com/ory-am/fosite Storage
mockgen -package internal -destination internal/authorize_code_storage.go github.com/ory-am/fosite/handler/core AuthorizeCodeStorage
mockgen -package internal -destination internal/access_token_storage.go github.com/ory-am/fosite/handler/core AccessTokenStorage
mockgen -package internal -destination internal/refresh_token_strategy.go github.com/ory-am/fosite/handler/core RefreshTokenStorage
mockgen -package internal -destination internal/core_client_storage.go github.com/ory-am/fosite/handler/core/client ClientCredentialsGrantStorage
mockgen -package internal -destination internal/core_explicit_storage.go github.com/ory-am/fosite/handler/core/explicit AuthorizeCodeGrantStorage
mockgen -package internal -destination internal/core_implicit_storage.go github.com/ory-am/fosite/handler/core/implicit ImplicitGrantStorage
mockgen -package internal -destination internal/core_owner_storage.go github.com/ory-am/fosite/handler/core/owner ResourceOwnerPasswordCredentialsGrantStorage
mockgen -package internal -destination internal/core_refresh_storage.go github.com/ory-am/fosite/handler/core/refresh RefreshTokenGrantStorage
mockgen -package internal -destination internal/oidc_id_token_storage.go github.com/ory-am/fosite/handler/oidc OpenIDConnectRequestStorage
mockgen -package internal -destination internal/access_token_strategy.go github.com/ory-am/fosite/handler/core AccessTokenStrategy
mockgen -package internal -destination internal/refresh_token_strategy.go github.com/ory-am/fosite/handler/core RefreshTokenStrategy
mockgen -package internal -destination internal/authorize_code_strategy.go github.com/ory-am/fosite/handler/core AuthorizeCodeStrategy
mockgen -package internal -destination internal/id_token_strategy.go github.com/ory-am/fosite/handler/oidc OpenIDConnectTokenStrategy
mockgen -package internal -destination internal/authorize_handler.go github.com/ory-am/fosite AuthorizeEndpointHandler
mockgen -package internal -destination internal/token_handler.go github.com/ory-am/fosite TokenEndpointHandler
mockgen -package internal -destination internal/validator.go github.com/ory-am/fosite AuthorizedRequestValidator
mockgen -package internal -destination internal/client.go github.com/ory-am/fosite Client
mockgen -package internal -destination internal/request.go github.com/ory-am/fosite Requester
mockgen -package internal -destination internal/access_request.go github.com/ory-am/fosite AccessRequester
mockgen -package internal -destination internal/access_response.go github.com/ory-am/fosite AccessResponder
mockgen -package internal -destination internal/authorize_request.go github.com/ory-am/fosite AuthorizeRequester
mockgen -package internal -destination internal/authorize_response.go github.com/ory-am/fosite AuthorizeResponder