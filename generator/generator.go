package generator

import "strings"

// Token represents an authorize code.
type Token struct {
	// Key is the code's key
	Key string

	// Signature is the key's hashed signature
	Signature string
}

// FromString extracts key and signature from "<key>.<signature>".
func (a *Token) FromString(data string) {
	a.Key = ""
	a.Signature = ""

	if data == "" {
		return
	}

	parts := strings.Split(data, ".")
	if len(parts) != 2 {
		return
	}

	key := strings.TrimSpace(parts[0])
	sig := strings.TrimSpace(parts[1])
	if key == "" || sig == "" {
		return
	}

	a.Key = key
	a.Signature = sig
	return
}

// String will return the authorize code as "<key>.<signature>".
func (a *Token) String() string {
	return a.Key + "." + a.Signature
}

// Generator provides a set of methods to create access, refresh and authorize tokens.
type Generator interface {
	// Generate generates a opaque and signed token.
	// RFC6749 does not require tokens to be opaque, but it is considered best practice.
	Generate() (*Token, error)

	// ValidateSignature verifies that the tokens key matches the tokens signature.
	ValidateSignature(token *Token) error
}
