package enigma

// Enigma provides a set of methods to create access, refresh and authorize tokens.
type Enigma interface {

	// GenerateChallenge generates a challenge (comparable to an opaque token).
	GenerateChallenge(secret []byte) (*Challenge, error)

	// ValidateSignature verifies that the challenge key matches the challenge signature, making the challenge
	// valid or returning an error if it is invalid.
	ValidateChallenge(secret []byte, challenge *Challenge) error
}
