package fosite

import (
	"net/http"

	"github.com/pkg/errors"
)

var (
	ErrRequestUnauthorized     = errors.New("The request could not be authorized")
	ErrRequestForbidden        = errors.New("The request is not allowed")
	ErrInvalidRequest          = errors.New("The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed")
	ErrUnauthorizedClient      = errors.New("The client is not authorized to request a token using this method")
	ErrAccessDenied            = errors.New("The resource owner or authorization server denied the request")
	ErrUnsupportedResponseType = errors.New("The authorization server does not support obtaining a token using this method")
	ErrInvalidScope            = errors.New("The requested scope is invalid, unknown, or malformed")
	ErrServerError             = errors.New("The authorization server encountered an unexpected condition that prevented it from fulfilling the request")
	ErrTemporarilyUnavailable  = errors.New("The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server")
	ErrUnsupportedGrantType    = errors.New("The authorization grant type is not supported by the authorization server")
	ErrInvalidGrant            = errors.New("The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client")
	ErrInvalidClient           = errors.New("Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)")
	ErrInvalidState            = errors.Errorf("The state is missing or has less than %d characters and is therefore considered too weak", MinParameterEntropy)
	ErrInsufficientEntropy     = errors.Errorf("The request used a security parameter (e.g., anti-replay, anti-csrf) with insufficient entropy (minimum of %d characters)", MinParameterEntropy)
	ErrMisconfiguration        = errors.New("The request failed because of an internal error that is probably caused by misconfiguration")
	ErrNotFound                = errors.New("Could not find the requested resource(s)")
	ErrInvalidTokenFormat      = errors.New("Invalid token format")
	ErrTokenSignatureMismatch  = errors.New("Token signature mismatch")
	ErrTokenExpired            = errors.New("Token expired")
	ErrScopeNotGranted         = errors.New("The token was not granted the requested scope")
	ErrTokenClaim              = errors.New("The token failed validation due to a claim mismatch")
	ErrInactiveToken           = errors.New("Token is inactive because it is malformed, expired or otherwise invalid")
)

const (
	errRequestUnauthorized         = "request_unauthorized"
	errRequestForbidden            = "request_forbidden"
	errInvalidRequestName          = "invalid_request"
	errUnauthorizedClientName      = "unauthorized_client"
	errAccessDeniedName            = "access_denied"
	errUnsupportedResponseTypeName = "unsupported_response_type"
	errInvalidScopeName            = "invalid_scope"
	errServerErrorName             = "server_error"
	errTemporarilyUnavailableName  = "temporarily_unavailable"
	errUnsupportedGrantTypeName    = "unsupported_grant_type"
	errInvalidGrantName            = "invalid_grant"
	errInvalidClientName           = "invalid_client"
	UnknownErrorName               = "unknown_error"
	errNotFound                    = "not_found"
	errInvalidState                = "invalid_state"
	errMisconfiguration            = "misconfiguration"
	errInsufficientEntropy         = "insufficient_entropy"
	errInvalidTokenFormat          = "invalid_token"
	errTokenSignatureMismatch      = "token_signature_mismatch"
	errTokenExpired                = "token_expired"
	errScopeNotGranted             = "scope_not_granted"
	errTokenClaim                  = "token_claim"
	errTokenInactive               = "token_inactive"
)

type RFC6749Error struct {
	Name        string `json:"error"`
	Description string `json:"error_description"`
	Hint        string `json:"-"`
	Code        int    `json:"statusCode"`
	Debug       string `json:"-"`
}

func ErrorToRFC6749Error(err error) *RFC6749Error {
	if e, ok := err.(*RFC6749Error); ok {
		return e
	}

	switch errors.Cause(err) {
	case ErrInactiveToken:
		{
			{
				return &RFC6749Error{
					Name:        errTokenInactive,
					Description: ErrInactiveToken.Error(),
					Debug:       err.Error(),
					Hint:        "Token validation failed.",
					Code:        http.StatusUnauthorized,
				}
			}
		}
	case ErrTokenClaim:
		{
			return &RFC6749Error{
				Name:        errTokenClaim,
				Description: ErrTokenClaim.Error(),
				Debug:       err.Error(),
				Hint:        "One or more token claims failed validation.",
				Code:        http.StatusUnauthorized,
			}
		}
	case ErrScopeNotGranted:
		{
			return &RFC6749Error{
				Name:        errScopeNotGranted,
				Description: ErrScopeNotGranted.Error(),
				Debug:       err.Error(),
				Hint:        "The resource owner did not grant the requested scope.",
				Code:        http.StatusForbidden,
			}
		}
	case ErrTokenExpired:
		{
			return &RFC6749Error{
				Name:        errTokenExpired,
				Description: ErrTokenExpired.Error(),
				Debug:       err.Error(),
				Hint:        "The token expired.",
				Code:        http.StatusUnauthorized,
			}
		}
	case ErrInvalidTokenFormat:
		{
			return &RFC6749Error{
				Name:        errInvalidTokenFormat,
				Description: ErrInvalidTokenFormat.Error(),
				Debug:       err.Error(),
				Hint:        "Check that you provided a valid token in the right format.",
				Code:        http.StatusBadRequest,
			}
		}
	case ErrTokenSignatureMismatch:
		{
			return &RFC6749Error{
				Name:        errTokenSignatureMismatch,
				Description: ErrTokenSignatureMismatch.Error(),
				Debug:       err.Error(),
				Hint:        "Check that you provided  a valid token in the right format.",
				Code:        http.StatusBadRequest,
			}
		}
	case ErrRequestUnauthorized:
		{
			return &RFC6749Error{
				Name:        errRequestUnauthorized,
				Description: ErrRequestUnauthorized.Error(),
				Debug:       err.Error(),
				Hint:        "Check that you provided valid credentials in the right format.",
				Code:        http.StatusUnauthorized,
			}
		}
	case ErrRequestForbidden:
		{
			return &RFC6749Error{
				Name:        errRequestForbidden,
				Description: ErrRequestForbidden.Error(),
				Debug:       err.Error(),
				Hint:        "You are not allowed to perform this action.",
				Code:        http.StatusForbidden,
			}
		}
	case ErrInvalidRequest:
		return &RFC6749Error{
			Name:        errInvalidRequestName,
			Description: ErrInvalidRequest.Error(),
			Debug:       err.Error(),
			Hint:        "Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
			Code:        http.StatusBadRequest,
		}
	case ErrUnauthorizedClient:
		return &RFC6749Error{
			Name:        errUnauthorizedClientName,
			Description: ErrUnauthorizedClient.Error(),
			Debug:       err.Error(),
			Hint:        "Make sure that client id and secret are correctly specified and that the client exists.",
			Code:        http.StatusUnauthorized,
		}
	case ErrAccessDenied:
		return &RFC6749Error{
			Name:        errAccessDeniedName,
			Description: ErrAccessDenied.Error(),
			Debug:       err.Error(),
			Hint:        "Make sure that the request you are making is valid. Maybe the credential or request parameters you are using are limited in scope or otherwise restricted.",
			Code:        http.StatusForbidden,
		}
	case ErrUnsupportedResponseType:
		return &RFC6749Error{
			Name:        errUnsupportedResponseTypeName,
			Description: ErrUnsupportedResponseType.Error(),
			Debug:       err.Error(),
			Code:        http.StatusBadRequest,
		}
	case ErrInvalidScope:
		return &RFC6749Error{
			Name:        errInvalidScopeName,
			Description: ErrInvalidScope.Error(),
			Debug:       err.Error(),
			Code:        http.StatusBadRequest,
		}
	case ErrServerError:
		return &RFC6749Error{
			Name:        errServerErrorName,
			Description: ErrServerError.Error(),
			Debug:       err.Error(),
			Code:        http.StatusInternalServerError,
		}
	case ErrTemporarilyUnavailable:
		return &RFC6749Error{
			Name:        errTemporarilyUnavailableName,
			Description: ErrTemporarilyUnavailable.Error(),
			Debug:       err.Error(),
			Code:        http.StatusServiceUnavailable,
		}
	case ErrUnsupportedGrantType:
		return &RFC6749Error{
			Name:        errUnsupportedGrantTypeName,
			Description: ErrUnsupportedGrantType.Error(),
			Debug:       err.Error(),
			Code:        http.StatusBadRequest,
		}
	case ErrInvalidGrant:
		return &RFC6749Error{
			Name:        errInvalidGrantName,
			Description: ErrInvalidGrant.Error(),
			Debug:       err.Error(),
			Code:        http.StatusBadRequest,
		}
	case ErrInvalidClient:
		return &RFC6749Error{
			Name:        errInvalidClientName,
			Description: ErrInvalidClient.Error(),
			Debug:       err.Error(),
			Code:        http.StatusUnauthorized,
		}
	case ErrInvalidState:
		return &RFC6749Error{
			Name:        errInvalidState,
			Description: ErrInvalidState.Error(),
			Debug:       err.Error(),
			Code:        http.StatusBadRequest,
		}
	case ErrInsufficientEntropy:
		return &RFC6749Error{
			Name:        errInsufficientEntropy,
			Description: ErrInsufficientEntropy.Error(),
			Debug:       err.Error(),
			Code:        http.StatusBadRequest,
		}
	case ErrMisconfiguration:
		return &RFC6749Error{
			Name:        errMisconfiguration,
			Description: ErrMisconfiguration.Error(),
			Debug:       err.Error(),
			Code:        http.StatusInternalServerError,
		}
	case ErrNotFound:
		return &RFC6749Error{
			Name:        errNotFound,
			Description: ErrNotFound.Error(),
			Debug:       err.Error(),
			Code:        http.StatusNotFound,
		}
	default:
		return &RFC6749Error{
			Name:        UnknownErrorName,
			Description: "The error is unrecognizable.",
			Debug:       err.Error(),
			Code:        http.StatusInternalServerError,
		}
	}
}

func (e *RFC6749Error) Status() string {
	return http.StatusText(e.Code)
}

func (e *RFC6749Error) Error() string {
	return e.Name
}

func (e *RFC6749Error) RequestID() string {
	return ""
}

func (e *RFC6749Error) Reason() string {
	return e.Hint
}

func (e *RFC6749Error) Details() []map[string]interface{} {
	return []map[string]interface{}{}
}

func (e *RFC6749Error) StatusCode() int {
	return e.Code
}
