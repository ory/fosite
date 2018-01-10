package pkce

import "fmt"

// VerifierStrategy defines PKCE verifier strategy contract
type VerifierStrategy interface {
	Compare(given, challenge string) bool
}

const (
	// Plain defines the plain verifier code
	Plain = "plain"
	// S256 defines the SHA-256 verifier code
	S256 = "s256"
)

// -----------------------------------------------------------------------------

var (
	verifiers = map[string]VerifierStrategy{}
)

// RegisterVerifier is used to register a verifier strategy. Panic if name
// already used.
// Additionnal verifiers could be externally registred with this function.
func RegisterVerifier(name string, verifier VerifierStrategy) {
	// Check if a verifier with same name does not exists
	if _, ok := verifiers[name]; ok {
		panic(fmt.Errorf("PKCE verifier '%s' already registered", name))
	}

	verifiers[name] = verifier
}

// GetVerifier returns the verifier strategy implementation according the given
// name
func GetVerifier(name string) VerifierStrategy {
	if v, ok := verifiers[name]; ok {
		return v
	}

	// No verifier strategy registered
	return nil
}
