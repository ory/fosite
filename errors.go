package fosite

import "github.com/go-errors/errors"

var (
	ErrInvalidRequest          = errors.New("The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.")
	ErrUnauthorizedClient      = errors.New("The client is not authorized to request a token using this method.")
	ErrAccessDenied            = errors.New("The resource owner or authorization server denied the request.")
	ErrUnsupportedResponseType = errors.New("The authorization server does not support obtaining a token using this method.")
	ErrInvalidScope            = errors.New("The requested scope is invalid, unknown, or malformed.")
	ErrServerError             = errors.New("The authorization server encountered an unexpected condition that prevented it from fulfilling the request.")
	ErrTemporarilyUnvailable   = errors.New("The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.")
	ErrUnsupportedGrantType    = errors.New("The authorization grant type is not supported by the authorization server.")
	ErrInvalidGrant            = errors.New("The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.")
	ErrInvalidClient           = errors.New("Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).")
)
