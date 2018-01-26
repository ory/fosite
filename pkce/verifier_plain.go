package pkce

import "crypto/subtle"

type plainVerifier struct {
}

// Compare given code verifier with challenge value using implemented strategy
func (v *plainVerifier) Compare(given, challenge string) bool {
	return subtle.ConstantTimeCompare([]byte(given), []byte(challenge)) == 1
}

// String returns the verifier string representation
func (v *plainVerifier) String() string {
	return Plain
}

func init() {
	RegisterVerifier(Plain, &plainVerifier{})
}
