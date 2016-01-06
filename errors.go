package fosite

import "github.com/go-errors/errors"

var (
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
	ErrInvalidState            = errors.Errorf("The state is missing or has less than %d characters and is therefore considered too weak", minStateLength)
)

const (
	errInvalidRequestName          = "invalid_request"
	errUnauthorizedClientName      = "unauthorized_client"
	errAccessDeniedName            = "acccess_denied"
	errUnsupportedResponseTypeName = "unsupported_response_type"
	errInvalidScopeName            = "invalid_scope"
	errServerErrorName             = "server_error"
	errTemporarilyUnavailableName  = "errTemporarilyUnavailableName"
	errUnsupportedGrantTypeName    = "unsupported_grant_type"
	errInvalidGrantName            = "invalid_grant"
	errInvalidClientName           = "invalid_client"
	errInvalidError                = "invalid_error"
	errInvalidState                = "invalid_state"
)

type RFC6749Error struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Hint        string `json:"-"`
}

func ErrorToRFC6749Error(err error) *RFC6749Error {
	ge, ok := err.(*errors.Error)
	if !ok {
		return &RFC6749Error{
			Name:        errInvalidError,
			Description: "The error is unrecognizable.",
			Hint:        err.Error(),
		}
	}
	if errors.Is(ge, ErrInvalidRequest) {
		return &RFC6749Error{
			Name:        errInvalidRequestName,
			Description: ge.Error(),
			Hint:        "Make sure that the various parameters are correct, be aware of case sensitivity and trim your parameters. Make sure that the client you are using has exactly whitelisted the redirect_uri you specified.",
		}
	} else if errors.Is(ge, ErrUnauthorizedClient) {
		return &RFC6749Error{
			Name:        errUnauthorizedClientName,
			Description: ge.Error(),
			Hint:        "Make sure that client id and secret are correctly specified and that the client exists.",
		}
	} else if errors.Is(ge, ErrAccessDenied) {
		return &RFC6749Error{
			Name:        errAccessDeniedName,
			Description: ge.Error(),
			Hint:        "Make sure that the request you are making is valid. Maybe the credential or request parameters you are using are limited in scope or otherwise restricted.",
		}
	} else if errors.Is(ge, ErrUnsupportedResponseType) {
		return &RFC6749Error{
			Name:        errUnsupportedResponseTypeName,
			Description: ge.Error(),
		}
	} else if errors.Is(ge, ErrInvalidScope) {
		return &RFC6749Error{
			Name:        errInvalidScopeName,
			Description: ge.Error(),
		}
	} else if errors.Is(ge, ErrServerError) {
		return &RFC6749Error{
			Name:        errServerErrorName,
			Description: ge.Error(),
		}
	} else if errors.Is(ge, ErrTemporarilyUnavailable) {
		return &RFC6749Error{
			Name:        errTemporarilyUnavailableName,
			Description: ge.Error(),
		}
	} else if errors.Is(ge, ErrUnsupportedGrantType) {
		return &RFC6749Error{
			Name:        errUnsupportedGrantTypeName,
			Description: ge.Error(),
		}
	} else if errors.Is(ge, ErrInvalidGrant) {
		return &RFC6749Error{
			Name:        errInvalidGrantName,
			Description: ge.Error(),
		}
	} else if errors.Is(ge, ErrInvalidClient) {
		return &RFC6749Error{
			Name:        errInvalidClientName,
			Description: ge.Error(),
		}
	} else if errors.Is(ge, ErrInvalidState) {
		return &RFC6749Error{
			Name:        errInvalidState,
			Description: ge.Error(),
		}
	}
	return &RFC6749Error{
		Name:        errInvalidError,
		Description: "The error is unrecognizable.",
		Hint:        ge.Error(),
	}
}
