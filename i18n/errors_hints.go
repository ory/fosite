package i18n

type ErrorHintType string

const (

	// generic hints

	ErrHintInternalError        ErrorHintType = "internal_error"
	ErrHintInvalidHTTPMethod    ErrorHintType = "invalid_http_method"
	ErrHintMalformedRequestBody ErrorHintType = "malformed_request_body"
	ErrHintEmptyRequestBody     ErrorHintType = "empty_request_body"

	// configuration

	ErrHintAdvancedOIDCNotAllowed                ErrorHintType = "oidc_not_allowed"
	ErrHintMissingClient                         ErrorHintType = "missing_client"
	ErrHintOIDCAuthMethodsNotAllowed             ErrorHintType = "oidc_auth_methods_not_allowed"
	ErrHintClientAuthNotSupported                ErrorHintType = "client_auth_not_supported"
	ErrHintClientAuthNotSupportedDuplicate       ErrorHintType = "client_auth_not_supported_dup"
	ErrHintClientAuthClientSecretJWTNotSupported ErrorHintType = "client_secret_jwt_not_supported"
	ErrHintMissingTokenEndpointURL               ErrorHintType = "missing_token_endpoint"
	ErrHintInsecureRedirectURLProtocol           ErrorHintType = "insecure_redirect_url_protocol"
	ErrHintAuthorizationGrantNotSupported        ErrorHintType = "authorization_grant_not_supported"
	ErrHintMisconfiguredAuthCode                 ErrorHintType = "misconfigured_auth_code"

	// generic OAuth

	ErrHintMissingGrantType                ErrorHintType = "missing_grant_type"
	ErrHintMalformedRequestAudience        ErrorHintType = "malformed_request_aud"
	ErrHintMalformedWhitelistAudience      ErrorHintType = "malformed_whitelist_aud"
	ErrHintAudienceNotAllowed              ErrorHintType = "aud_not_allowed"
	ErrHintRedirectURINotAllowed           ErrorHintType = "redirect_uri_not_allowed"
	ErrHintRequestScopeNotAllowed          ErrorHintType = "request_scp_not_allowed"
	ErrHintMissingResponseType             ErrorHintType = "missing_response_type"
	ErrHintResponseTypeNotAllowed          ErrorHintType = "response_type_not_allowed"
	ErrHintResponseModeNotAllowed          ErrorHintType = "response_mode_not_allowed"
	ErrHintResponseModeNotSupported        ErrorHintType = "response_mode_not_supported"
	ErrHintWeakStateEntropy                ErrorHintType = "weak_state_entropy"
	ErrHintWeakResponseModeForResponseType ErrorHintType = "weak_response_mode_for_response_type"
	ErrHintScopeNotGranted                 ErrorHintType = "scp_not_granted"
	ErrHintAccessTokenExpired              ErrorHintType = "access_token_expired"
	ErrHintRefreshTokenExpired             ErrorHintType = "refresh_token_expired"
	ErrHintInvalidCredentialFormat         ErrorHintType = "invalid_cred_format"
	ErrHintAuthCodeExpired                 ErrorHintType = "auth_code_expired"
	ErrHintHybridGrantMissingNonce         ErrorHintType = "hybrid_grant_missing_nonce"
	ErrHintWeakNonceEntropy                ErrorHintType = "weak_nonce_entropy"
	ErrHintImplicitGrantMissingNonce       ErrorHintType = "implicit_grant_missing_nonce"
	ErrHintPromptNoneNotAllowed            ErrorHintType = "prompt_none_not_allowed"
	ErrHintInvalidPromptValue              ErrorHintType = "invalid_prompt_value"
	ErrHintInvalidPromptNoneValue          ErrorHintType = "invalid_prompt_none_value"
	ErrHintPromptNoneLoginNotAllowed       ErrorHintType = "prompt_none_login_not_allowed"
	ErrHintPromptLoginNoReauth             ErrorHintType = "prompt_login_no_reauth"
	ErrHintIDTokenHintDecodeFailed         ErrorHintType = "id_token_hint_decode_failed"
	ErrHintIDTokenHintMissingSubject       ErrorHintType = "id_token_hint_missing_sub"
	ErrHintIDTokenSubjectMismatch          ErrorHintType = "id_token_sub_mismatch"

	// token validation

	ErrHintHTTPAuthzURLDecodeFailed          ErrorHintType = "httpauthz_urldecode_failed"
	ErrHintMissingClientCredentials          ErrorHintType = "missing_client_creds"
	ErrHintNoTokenValidationMethod           ErrorHintType = "no_token_validation_method"
	ErrHintIntrospectAndBearerTokenSame      ErrorHintType = "introspect_and_bearer_token_same"
	ErrHintInvalidHTTPAuthzHeader            ErrorHintType = "invalid_httpauthz_header"
	ErrHintIntrospectInvalidTokenType        ErrorHintType = "introspect_invalid_token_type"
	ErrHintMissingBasicAuthHeader            ErrorHintType = "missing_ba_header"
	ErrHintBasicAuthClientIDDecodeFailed     ErrorHintType = "ba_client_id_decode_failed"
	ErrHintBasicAuthClientSecretDecodeFailed ErrorHintType = "ba_client_secret_decode_failed"
	ErrHintBasicAuthClientNotFound           ErrorHintType = "ba_client_not_found"
	ErrHintInvalidClientCredentials          ErrorHintType = "invalid_client_creds"
	ErrHintInactiveIntrospectToken           ErrorHintType = "inactive_introspect_token"

	// token

	ErrHintAuthCodeReused                           ErrorHintType = "auth_code_reused"
	ErrHintAccessTokenRevokeFailed                  ErrorHintType = "access_token_revoke_failed"
	ErrHintRefreshTokenRevokeFailed                 ErrorHintType = "refresh_token_revoke_failed"
	ErrHintTokenClientIDMismatch                    ErrorHintType = "token_client_id_mismatch"
	ErrHintTokenRedirectURIMismatch                 ErrorHintType = "token_redirect_uri_mismatch"
	ErrHintClientCredentialsGrantNotAllowed         ErrorHintType = "client_credentials_grant_not_allowed"
	ErrHintRefreshTokenNoScopeGranted               ErrorHintType = "refresh_token_no_scope_granted"
	ErrHintRefreshTokenClientIDMismatch             ErrorHintType = "refresh_token_client_id_mismatch"
	ErrHintRefreshTokenConcurrentRequestsNotAllowed ErrorHintType = "refresh_token_concurrent_requests_not_allowed"
	ErrHintMissingROPCCredentials                   ErrorHintType = "missing_ropc_credentials"
	ErrHintROPCAuthFailed                           ErrorHintType = "ropc_auth_failed"

	// JSON web keys

	ErrHintJWKFetchError         ErrorHintType = "jwk_fetch_error"
	ErrHintJWKFetchBadStatus     ErrorHintType = "jwk_fetch_bad_status"
	ErrHintMalformedJWKFetchBody ErrorHintType = "malformed_jwk_fetch_body"
	ErrHintMissingJWK            ErrorHintType = "missing_jwk"

	// JSON web token

	ErrHintJWTKidNotFound       ErrorHintType = "jwt_kid_not_found"
	ErrHintJWSKeyNotFoundForAlg ErrorHintType = "jws_key_not_found_for_alg"

	// PKCE

	ErrHintMissingPKCECodeChallenge                ErrorHintType = "missing_pkce_code_challenge"
	ErrHintMissingPKCECodeChallengeForPublicClient ErrorHintType = "missing_pkce_code_challenge_for_pub_client"
	ErrHintInvalidPKCECodeChallengeMethod          ErrorHintType = "invalid_pkce_code_challenge_method"
	ErrHintMissingPKCERequestData                  ErrorHintType = "missing_pkce_request_data"
	ErrHintPKCEVerifierTooSmall                    ErrorHintType = "pkce_verifier_too_small"
	ErrHintPKCEVerifierTooLong                     ErrorHintType = "pkce_verifier_too_long"
	ErrHintInvalidPKCEVerifierCharSet              ErrorHintType = "invalid_pkce_verifier_charset"
	ErrHintPKCEVerifierMismatch                    ErrorHintType = "pkce_verifier_mismatch"

	// client assertion

	ErrHintMissingClientAssertion                  ErrorHintType = "missing_client_assertion"
	ErrHintMissingClientAssertionDuplicate         ErrorHintType = "missing_client_assertion_dup"
	ErrHintMissingClientAssertionSubject           ErrorHintType = "missing_client_assertion_sub"
	ErrHintMissingClientAssertionSubjectDuplicate  ErrorHintType = "missing_client_assertion_sub_dup"
	ErrHintNoClientAuthAllowed                     ErrorHintType = "no_client_auth_allowed"
	ErrHintClientAssertionNotSupported             ErrorHintType = "client_assertion_not_supported"
	ErrHintClientAssertionSigningAlgNotSupported   ErrorHintType = "client_assertion_signing_algo_not_supported"
	ErrHintClientAssertionParsingError             ErrorHintType = "client_assertion_parsing_error"
	ErrHintClientAssertionVerifyError              ErrorHintType = "client_assertion_verify_error"
	ErrHintClientAssertionVerifyErrorDuplicate     ErrorHintType = "client_assertion_verify_error_dup"
	ErrHintClientAssertionClaimsVerifyError        ErrorHintType = "client_assertion_claims_verify_error"
	ErrHintInvalidClientAssertionIssuer            ErrorHintType = "invalid_client_assertion_iss"
	ErrHintMissingClientAssertionIssuer            ErrorHintType = "missing_client_assertion_iss"
	ErrHintInvalidClientAssertionSubject           ErrorHintType = "invalid_client_assertion_sub"
	ErrHintMissingClientAssertionJTI               ErrorHintType = "missing_client_assertion_jti"
	ErrHintMissingClientAssertionJTIDuplicate      ErrorHintType = "missing_client_assertion_jti_dup"
	ErrHintMissingClientAssertionIssuedAt          ErrorHintType = "missing_client_assertion_iat"
	ErrHintMissingClientAssertionExpiry            ErrorHintType = "missing_client_assertion_exp"
	ErrHintInvalidClientAssertionAudience          ErrorHintType = "invalid_client_assertion_aud"
	ErrHintInvalidClientAssertionAudienceDuplicate ErrorHintType = "invalid_client_assertion_aud_dup"
	ErrHintMissingClientAssertionClaims            ErrorHintType = "missing_client_assertion_claims"
	ErrHintClientAssertionJTIReused                ErrorHintType = "client_assertion_jti_reused"
	ErrHintInvalidClientAssertionExpiryTimeType    ErrorHintType = "invalid_client_assertion_expiry_time_type"
	ErrHintInvalidClientAssertionType              ErrorHintType = "invalid_client_assertion_type"
	ErrHintInvalidClientAssertionSessionType       ErrorHintType = "invalid_client_assertion_session_type"
	ErrHintClientAssertionValidityTooLong          ErrorHintType = "client_assertion_validity_too_long"
	ErrHintClientAssertionNotValidYet              ErrorHintType = "client_assertion_not_valid_yet"
	ErrHintClientAssertionExpired                  ErrorHintType = "client_assertion_expired"
	ErrHintClientAssertionNoPublicJWKConfigured    ErrorHintType = "client_assertion_no_public_jwk_configured"
	ErrHintClientAssertionScopeNotAllowed          ErrorHintType = "client_assertion_scp_not_allowed"

	// request/request object

	ErrHintRequestURINotWhitelisted       ErrorHintType = "request_uri_not_whitelisted"
	ErrHintRequestURIFetchError           ErrorHintType = "request_uri_fetch_error"
	ErrHintRequestURIFetchBadStatus       ErrorHintType = "request_uri_fetch_bad_status"
	ErrHintMalformedRequestURIBody        ErrorHintType = "malformed_request_uri_body"
	ErrHintRequestSigningAlgoNotAllowed   ErrorHintType = "request_signing_algo_not_allowed"
	ErrHintMissingRequestSigningKey       ErrorHintType = "missing_request_signing_key"
	ErrHintRequestSigningAlgoNotSupported ErrorHintType = "request_signing_algo_not_supported"
	ErrHintRequestSignVerificationFailed  ErrorHintType = "request_sign_verification_failed"
	ErrHintInvalidRequestClaims           ErrorHintType = "invalid_request_claims"
	ErrHintInvalidRequestURI              ErrorHintType = "invalid_request_uri"
	ErrHintRequestAndRequestURINotAllowed ErrorHintType = "request_and_request_uri_not_allowed"
	ErrHintMissingRequestJSONWebKeys      ErrorHintType = "missing_request_jwk"
)

var (
	HintsMap = map[ErrorHintType]string{
		ErrHintInvalidHTTPMethod:                        "HTTP method is '%s', expected 'POST'.",
		ErrHintMalformedRequestBody:                     "Unable to parse HTTP body, make sure to send a properly formatted form request body.",
		ErrHintEmptyRequestBody:                         "The POST body can not be empty.",
		ErrHintMissingGrantType:                         "Request parameter 'grant_type' is missing",
		ErrHintInternalError:                            "An internal server occurred while trying to complete the request.",
		ErrHintMalformedRequestAudience:                 "Unable to parse requested audience '%s'.",
		ErrHintMalformedWhitelistAudience:               "Unable to parse whitelisted audience '%s'.",
		ErrHintAudienceNotAllowed:                       "Requested audience '%s' has not been whitelisted by the OAuth 2.0 Client.",
		ErrHintRedirectURINotAllowed:                    "The 'redirect_uri' parameter does not match any of the OAuth 2.0 Client's pre-registered redirect urls.",
		ErrHintRequestAndRequestURINotAllowed:           "OpenID Connect parameters 'request' and 'request_uri' were both given, but you can use at most one.",
		ErrHintAdvancedOIDCNotAllowed:                   "OpenID Connect '%s' context was given, but the OAuth 2.0 Client does not implement advanced OpenID Connect capabilities.",
		ErrHintMissingRequestJSONWebKeys:                "OpenID Connect 'request' or 'request_uri' context was given, but the OAuth 2.0 Client does not have any JSON Web Keys registered.",
		ErrHintRequestURINotWhitelisted:                 "Request URI '%s' is not whitelisted by the OAuth 2.0 Client.",
		ErrHintRequestURIFetchError:                     "Unable to fetch OpenID Connect request parameters from 'request_uri' because: %s.",
		ErrHintRequestURIFetchBadStatus:                 "Unable to fetch OpenID Connect request parameters from 'request_uri' because status code '%d' was expected, but got '%d'.",
		ErrHintMalformedRequestURIBody:                  "Unable to fetch OpenID Connect request parameters from 'request_uri' because body parsing failed with: %s.",
		ErrHintRequestSigningAlgoNotAllowed:             "The request object uses signing algorithm '%[1]s', but the requested OAuth 2.0 Client enforces signing algorithm '%[2]s'.",
		ErrHintMissingRequestSigningKey:                 "Unable to retrieve %s signing key from OAuth 2.0 Client.",
		ErrHintRequestSigningAlgoNotSupported:           "This request object uses unsupported signing algorithm '%s'.",
		ErrHintRequestSignVerificationFailed:            "Unable to verify the request object's signature.",
		ErrHintInvalidRequestClaims:                     "Unable to verify the request object because its claims could not be validated, check if the expiry time is set correctly.",
		ErrHintInvalidRequestURI:                        "The redirect URI '%s' contains an illegal character (for example #) or is otherwise invalid.",
		ErrHintRequestScopeNotAllowed:                   "The OAuth 2.0 Client is not allowed to request scope '%s'.",
		ErrHintMissingResponseType:                      "The request is missing the 'response_type' parameter.",
		ErrHintResponseTypeNotAllowed:                   "The client is not allowed to request response_type '%s'.",
		ErrHintResponseModeNotAllowed:                   "The request has response_mode \"%s\". set but registered OAuth 2.0 client doesn't support response_mode",
		ErrHintResponseModeNotSupported:                 "The client is not allowed to request response_mode '%s'.",
		ErrHintMissingClient:                            "The requested OAuth 2.0 Client does not exist.",
		ErrHintWeakStateEntropy:                         "Request parameter 'state' must be at least be %d characters long to ensure sufficient entropy.",
		ErrHintWeakResponseModeForResponseType:          "Insecure response_mode '%[1]s' for the response_type '%[2]s'.",
		ErrHintJWKFetchError:                            "Unable to fetch JSON Web Keys from location '%s'. Check for typos or other network issues.",
		ErrHintJWKFetchBadStatus:                        "Expected successful status code in range of 200 - 399 from location '%s' but received code %d.",
		ErrHintMalformedJWKFetchBody:                    "Unable to decode JSON Web Keys from location '%s'. Please check for typos and if the URL returns valid JSON.",
		ErrHintMissingJWK:                               "The OAuth 2.0 Client has no JSON Web Keys set registered, but they are needed to complete the request.",
		ErrHintMissingClientAssertion:                   "The client_assertion request parameter must be set when using client_assertion_type of '%s'.",
		ErrHintMissingClientAssertionSubject:            "The claim 'sub' from the client_assertion JSON Web Token is undefined.",
		ErrHintOIDCAuthMethodsNotAllowed:                "The server configuration does not support OpenID Connect specific authentication methods.",
		ErrHintNoClientAuthAllowed:                      "This requested OAuth 2.0 client does not support client authentication, however 'client_assertion' was provided in the request.",
		ErrHintClientAssertionNotSupported:              "This requested OAuth 2.0 client only supports client authentication method '%s', however 'client_assertion' was provided in the request.",
		ErrHintClientAuthNotSupported:                   "This requested OAuth 2.0 client only supports client authentication method '%s', however that method is not supported by this server.",
		ErrHintClientAssertionSigningAlgNotSupported:    "The 'client_assertion' uses signing algorithm '%[1]s' but the requested OAuth 2.0 Client enforces signing algorithm '%[2]s'.",
		ErrHintClientAuthClientSecretJWTNotSupported:    "This authorization server does not support client authentication method 'client_secret_jwt'.",
		ErrHintClientAssertionVerifyError:               "Unable to verify the integrity of the 'client_assertion' value.",
		ErrHintClientAssertionClaimsVerifyError:         "Unable to verify the request object because its claims could not be validated, check if the expiry time is set correctly.",
		ErrHintInvalidClientAssertionIssuer:             "Claim 'iss' from 'client_assertion' must match the 'client_id' of the OAuth 2.0 Client.",
		ErrHintMissingTokenEndpointURL:                  "The authorization server's token endpoint URL has not been set.",
		ErrHintInvalidClientAssertionSubject:            "Claim 'sub' from 'client_assertion' must match the 'client_id' of the OAuth 2.0 Client.",
		ErrHintMissingClientAssertionJTI:                "Claim 'jti' from 'client_assertion' must be set but is not.",
		ErrHintClientAssertionJTIReused:                 "Claim 'jti' from 'client_assertion' MUST only be used once.",
		ErrHintInvalidClientAssertionExpiryTimeType:     "Unable to type assert the expiry time from claims. This should not happen as we validate the expiry time already earlier with token.Claims.Valid()",
		ErrHintInvalidClientAssertionAudience:           "Claim 'audience' from 'client_assertion' must match the authorization server's token endpoint '%s'.",
		ErrHintInvalidClientAssertionType:               "Unknown client_assertion_type '%s'.",
		ErrHintClientAuthNotSupportedDuplicate:          "The OAuth 2.0 Client supports client authentication method '%[1]s', but method '%[2]s' was requested. You must configure the OAuth 2.0 client's 'token_endpoint_auth_method' value to accept '%[2]s'.",
		ErrHintJWTKidNotFound:                           "The JSON Web Token uses signing key with kid '%s', which could not be found.",
		ErrHintJWSKeyNotFoundForAlg:                     "Unable to find %[1]s public key with use='sig' for kid '%[2]s' in JSON Web Key Set.",
		ErrHintHTTPAuthzURLDecodeFailed:                 "The %s in the HTTP authorization header could not be decoded from 'application/x-www-form-urlencoded'.",
		ErrHintMissingClientCredentials:                 "Client credentials missing or malformed in both HTTP Authorization header and HTTP POST body.",
		ErrHintNoTokenValidationMethod:                  "Unable to find a suitable validation strategy for the token, thus it is invalid.",
		ErrHintIntrospectAndBearerTokenSame:             "Bearer and introspection token are identical.",
		ErrHintInvalidHTTPAuthzHeader:                   "HTTP Authorization header missing, malformed, or credentials used are invalid.",
		ErrHintIntrospectInvalidTokenType:               "HTTP Authorization header did not provide a token of type '%[1]s', got type '%[2]s'.",
		ErrHintMissingBasicAuthHeader:                   "HTTP Authorization header missing.",
		ErrHintBasicAuthClientIDDecodeFailed:            "Unable to decode OAuth 2.0 Client ID from HTTP basic authorization header, make sure it is properly encoded.",
		ErrHintBasicAuthClientSecretDecodeFailed:        "Unable to decode OAuth 2.0 Client Secret from HTTP basic authorization header, make sure it is properly encoded.",
		ErrHintBasicAuthClientNotFound:                  "Unable to find OAuth 2.0 Client from HTTP basic authorization header.",
		ErrHintInvalidClientCredentials:                 "OAuth 2.0 Client credentials are invalid.",
		ErrHintInactiveIntrospectToken:                  "An introspection strategy indicated that the token is inactive.",
		ErrHintInsecureRedirectURLProtocol:              "Redirect URL is using an insecure protocol, http is only allowed for hosts with suffix `localhost`, for example: http://myapp.localhost/.",
		ErrHintAuthorizationGrantNotSupported:           "The OAuth 2.0 Client is not allowed to use authorization grant '%s'.",
		ErrHintAuthCodeReused:                           "The authorization code has already been used.",
		ErrHintAccessTokenRevokeFailed:                  "Additionally, an error occurred during processing the access token revocation.",
		ErrHintRefreshTokenRevokeFailed:                 "Additionally, an error occurred during processing the refresh token revocation.",
		ErrHintTokenClientIDMismatch:                    "The OAuth 2.0 Client ID from this request does not match the one from the authorize request.",
		ErrHintTokenRedirectURIMismatch:                 "The \"redirect_uri\" from this request does not match the one from the authorize request.",
		ErrHintMisconfiguredAuthCode:                    "Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.",
		ErrHintClientCredentialsGrantNotAllowed:         "The OAuth 2.0 Client is marked as public and is thus not allowed to use authorization grant 'client_credentials'.",
		ErrHintRefreshTokenNoScopeGranted:               "The OAuth 2.0 Client was not granted scope %s and may thus not perform the 'refresh_token' authorization grant.",
		ErrHintRefreshTokenClientIDMismatch:             "The OAuth 2.0 Client ID from this request does not match the ID during the initial token issuance.",
		ErrHintRefreshTokenConcurrentRequestsNotAllowed: "Failed to refresh token because of multiple concurrent requests using the same token which is not allowed.",
		ErrHintMissingROPCCredentials:                   "Username or password are missing from the POST body.",
		ErrHintROPCAuthFailed:                           "Unable to authenticate the provided username and password credentials.",
		ErrHintScopeNotGranted:                          "The request scope '%s' has not been granted or is not allowed to be requested.",
		ErrHintAccessTokenExpired:                       "Access token expired at '%s'.",
		ErrHintRefreshTokenExpired:                      "Refresh token expired at '%s'.",
		ErrHintAuthCodeExpired:                          "Authorize code expired at '%s'.",
		ErrHintHybridGrantMissingNonce:                  "Parameter 'nonce' must be set when requesting an ID Token using the OpenID Connect Hybrid Flow.",
		ErrHintWeakNonceEntropy:                         "Parameter 'nonce' is set but does not satisfy the minimum entropy of %d characters.",
		ErrHintImplicitGrantMissingNonce:                "Parameter 'nonce' must be set when using the OpenID Connect Implicit Flow.",
		ErrHintPromptNoneNotAllowed:                     "OAuth 2.0 Client is marked public and redirect uri is not considered secure (https missing), but \"prompt=none\" was requested.",
		ErrHintInvalidPromptValue:                       "Used unknown value '%s' for prompt parameter",
		ErrHintInvalidPromptNoneValue:                   "Parameter 'prompt' was set to 'none', but contains other values as well which is not allowed.",
		ErrHintPromptNoneLoginNotAllowed:                "Failed to validate OpenID Connect request because prompt was set to 'none' but auth_time ('%[1]s') happened after the authorization request ('%[2]s') was registered, indicating that the user was logged in during this request which is not allowed.",
		ErrHintPromptLoginNoReauth:                      "Failed to validate OpenID Connect request because prompt was set to 'login' but auth_time ('%[1]s') happened before the authorization request ('%[2]s') was registered, indicating that the user was not re-authenticated which is forbidden.",
		ErrHintIDTokenHintDecodeFailed:                  "Failed to validate OpenID Connect request as decoding id token from id_token_hint parameter failed.",
		ErrHintIDTokenHintMissingSubject:                "Failed to validate OpenID Connect request because provided id token from id_token_hint does not have a subject.",
		ErrHintIDTokenSubjectMismatch:                   "Failed to validate OpenID Connect request because the subject from provided id token from id_token_hint does not match the current session's subject.",
		ErrHintMissingPKCECodeChallenge:                 "Clients must include a code_challenge when performing the authorize code flow, but it is missing.",
		ErrHintMissingPKCECodeChallengeForPublicClient:  "This client must include a code_challenge when performing the authorize code flow, but it is missing.",
		ErrHintInvalidPKCECodeChallengeMethod:           "Clients must use code_challenge_method=%s.",
		ErrHintMissingPKCERequestData:                   "Unable to find initial PKCE data tied to this request",
		ErrHintPKCEVerifierTooSmall:                     "The PKCE code verifier must be at least 43 characters.",
		ErrHintPKCEVerifierTooLong:                      "The PKCE code verifier can not be longer than 128 characters.",
		ErrHintInvalidPKCEVerifierCharSet:               "The PKCE code verifier must only contain [a-Z], [0-9], '-', '.', '_', '~'.",
		ErrHintPKCEVerifierMismatch:                     "The PKCE code challenge did not match the code verifier.",
		ErrHintMissingClientAssertionDuplicate:          "The assertion request parameter must be set when using grant_type of '%s'.",
		ErrHintClientAssertionParsingError:              "Unable to parse JSON Web Token passed in \"assertion\" request parameter.",
		ErrHintClientAssertionVerifyErrorDuplicate:      "Unable to verify the integrity of the 'assertion' value.",
		ErrHintClientAssertionScopeNotAllowed:           "The public key registered for issuer \"%[1]s\" and subject \"%[2]s\" is not allowed to request scope \"%[3]s\".",
		ErrHintMissingClientAssertionClaims:             "Looks like there are no claims in JWT in \"assertion\" request parameter.",
		ErrHintMissingClientAssertionIssuer:             "The JWT in \"assertion\" request parameter MUST contain an \"iss\" (issuer) claim.",
		ErrHintMissingClientAssertionSubjectDuplicate:   "The JWT in \"assertion\" request parameter MUST contain a \"sub\" (subject) claim.",
		ErrHintInvalidClientAssertionAudienceDuplicate:  "The JWT in \"assertion\" request parameter MUST contain an \"aud\" (audience) claim.",
		ErrHintMissingClientAssertionExpiry:             "The JWT in \"assertion\" request parameter MUST contain an \"exp\" (expiration time) claim.",
		ErrHintMissingClientAssertionIssuedAt:           "The JWT in \"assertion\" request parameter MUST contain an \"iat\" (issued at) claim.",
		ErrHintMissingClientAssertionJTIDuplicate:       "The JWT in \"assertion\" request parameter MUST contain an \"jti\" (JWT ID) claim.",
		ErrHintClientAssertionNoPublicJWKConfigured:     "No public JWK was registered for issuer \"%[1]s\" and subject \"%[2]s\", and public key is required to check signature of JWT in \"assertion\" request parameter.",
		ErrHintClientAssertionExpired:                   "The JWT in \"assertion\" request parameter expired.",
		ErrHintClientAssertionNotValidYet:               "The JWT in \"assertion\" request parameter contains an \"nbf\" (not before) claim, that identifies the time '%s' before which the token MUST NOT be accepted.",
		ErrHintClientAssertionValidityTooLong:           "The JWT in \"assertion\" request parameter contains an \"exp\" (expiration time) claim with value \"%[1]s\" that is unreasonably far in the future, considering token issued at \"%[2]s\".",
		ErrHintInvalidClientAssertionSessionType:        "Session must be of type *rfc7523.Session but got type: %T",
		ErrHintInvalidCredentialFormat:                  "Check that you provided valid credentials in the right format.",
	}
)
