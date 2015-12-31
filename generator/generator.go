package generator

import "strings"

// AuthorizeCode represents an authorize code.
type AuthorizeCode struct {
	// Key is the code's key
	Key string

	// Signature is the key's hashed signature
	Signature string
}

// FromString extracts key and signature from "<key>.<signature>"
func (a *AuthorizeCode) FromString(data string) {
	if data == "" {
		return
	}

	parts := strings.Split(data, ".")
	if len(parts) != 2 {
		return
	}

	a.Key = parts[0]
	a.Signature = parts[1]
	return
}

// String will return the authorize code as "<key>.<signature>"
func (a *AuthorizeCode) String() string {
	return a.Key + "." + a.Signature
}

// Generator provides a set of methods to create access, refresh and authorize tokens.
type Generator interface {

	// GenerateAccessToken generates an access token.
	// Spec does not require tokens to be opaque but it is considered best practice.
	GenerateAccessToken() (string, error)

	// GenerateAccessToken generates a refresh token.
	// Spec does not require tokens to be opaque but it is considered best practice.
	GenerateRefreshToken() (string, error)

	// GenerateAccessToken generates a authorize code.
	// Spec does not require tokens to be opaque but it is considered best practice.
	GenerateAuthorizeCode() (AuthorizeCode, error)

	ValidateAuthorizeCodeSignature(code string) (AuthorizeCode, error)
}