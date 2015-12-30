package hash

// Hasher defines how a oauth2-compatible hasher should look like
type Hasher interface {
	// Compare compares data with a hash and returns an error
	// if the two do not match.
	Compare(hash, data string) error

	// Hash creates a hash from data or returns an error.
	Hash(data string) (string, error)
}
