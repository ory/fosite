package generator

import (
	"github.com/ory-am/fosite/rand"
	"encoding/base64"
	"github.com/ory-am/fosite/hash"
"github.com/go-errors/errors"
)

type CryptoGenerator struct {
	AuthCodeEntropy int
	Hasher hash.Hasher
}

// Default of 32 bytes * 8 = 256 bit which is >= 128 bits as recommended by rfc6819 section 5.1.4.2.2.
const minimumEntropy = 32

// GenerateAuthorizeCode generates a new authorize code or returns an error.
// This method implements rfc6819 Section 5.1.4.2.2: Use High Entropy for Secrets
func (c *CryptoGenerator) GenerateAuthorizeCode() (*AuthorizeCode, error) {
	if c.AuthCodeEntropy < minimumEntropy {
		c.AuthCodeEntropy = minimumEntropy
	}

	// When creating secrets not intended for usage by human users (e.g.,
	// client secrets or token handles), the authorization server should
	// include a reasonable level of entropy in order to mitigate the risk
	// of guessing attacks.  The token value should be >=128 bits long and
	// constructed from a cryptographically strong random or pseudo-random
	// number sequence (see [RFC4086] for best current practice) generated
	// by the authorization server.
	bytes, err := rand.RandomBytes(c.AuthCodeEntropy, 10)
	if err != nil {
		return nil, err
	}

	hash, err := c.Hasher.Hash(bytes)
	if err != nil {
		return nil, err
	}

	var result []byte
	if _, err = base64.RawURLEncoding.Decode(&result, bytes); err != nil {
		return nil, err
	}

	return &AuthorizeCode{
		Key: result,
		Signature: hash,
	}, nil
}

// ValidateAuthorizeCodeSignature returns an AuthorizeCode, if the code argument is a valid authorize code
// and the signature matches the key.
func (c *CryptoGenerator) ValidateAuthorizeCodeSignature(code string) (ac *AuthorizeCode,err error) {
	ac.FromString(code)
	if ac.Key == "" || ac.Signature == "" {
		return nil, errors.New("Key and signature must both be not empty")
	}

	var result []byte
	if _, err = base64.RawURLEncoding.Encode(&result, []byte(ac.Key)); err != nil {
		// Not valid base64 decoding
		return nil, err
	}

	if err := c.Hasher.Compare([]byte(ac.Signature), result); err != nil {
		// Hash is invalid
		return nil, err
	}

	return ac
}