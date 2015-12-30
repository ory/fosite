package fosite

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
	GenerateAuthorizeCode() (string, error)
}