package pkce

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

type s256Verifier struct {
}

// Compare given code verifier with challenge value using implemented strategy
func (v *s256Verifier) Compare(given, challenge string) bool {
	// SHA-256, Blake2b one day maybe ...
	hash := sha256.Sum256([]byte(given))
	codeVerifier := base64.RawURLEncoding.EncodeToString(hash[:])

	return subtle.ConstantTimeCompare([]byte(codeVerifier), []byte(challenge)) == 1
}

// String returns the verifier string representation
func (v *s256Verifier) String() string {
	return S256
}

func init() {
	RegisterVerifier(S256, &s256Verifier{})
}
