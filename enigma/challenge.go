package enigma

import "strings"

// Challenge represents an validatable token.
type Challenge struct {
	// Key is the messages's key
	Key string

	// Signature is the messages's signature
	Signature string
}

// FromString extracts key and signature from "<key>.<signature>".
func (a *Challenge) FromString(data string) {
	a.Key = ""
	a.Signature = ""

	if data == "" {
		return
	}

	// All standard Bearer tokens contains 2 parts. JWT´s contain 3 parts
	parts := strings.Split(data, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return
	}

	var key, sig string
	if len(parts) == 2 {
		// HMAC, ...
		key = strings.TrimSpace(parts[0])
		sig = strings.TrimSpace(parts[1]) // Signature
	} else if len(parts) == 3 {
		// JWT
		key = strings.TrimSpace(parts[0]) + "." + strings.TrimSpace(parts[1]) // Header + Payload
		sig = strings.TrimSpace(parts[2])                                     // Signature
	}

	if key == "" || sig == "" {
		return
	}

	a.Key = key
	a.Signature = sig
	return
}

// String will return the Challenge as "<key>.<signature>".
func (a *Challenge) String() string {
	return a.Key + "." + a.Signature
}
