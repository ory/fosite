package generator

import (
	"bytes"
	"encoding/base64"
	"github.com/go-errors/errors"
	"github.com/ory-am/fosite/hash"
	"github.com/ory-am/fosite/rand"
)

type CryptoGenerator struct {
	AuthCodeEntropy int
	Hasher          hash.Hasher
}

// Default of 32 bytes * 8 = 256 bit which is >= 128 bits as recommended by rfc6819 section 5.1.4.2.2.
const minimumEntropy = 32

// GenerateAuthorizeCode generates a new authorize code or returns an error.
// This method implements rfc6819 Section 5.1.4.2.2: Use High Entropy for Secrets.
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
	randomBytes, err := rand.RandomBytes(c.AuthCodeEntropy, 20)
	if err != nil {
		return nil, err
	}

	resultKey := make([]byte, base64.StdEncoding.EncodedLen(c.AuthCodeEntropy))
	base64.RawStdEncoding.Encode(resultKey, randomBytes)
	resultKey = bytes.Trim(resultKey, "\x00")

	hash, err := c.Hasher.Hash(resultKey)
	if err != nil {
		return nil, err
	}

	resultHash := make([]byte, base64.StdEncoding.EncodedLen(len(hash)))
	base64.RawStdEncoding.Encode(resultHash, hash)
	resultHash = bytes.Trim(resultHash, "\x00")

	return &AuthorizeCode{
		Key:       string(resultKey),
		Signature: string(resultHash),
	}, nil
}

// ValidateAuthorizeCodeSignature returns an AuthorizeCode, if the code argument is a valid authorize code
// and the signature matches the key.
func (c *CryptoGenerator) ValidateAuthorizeCode(code string) (ac *AuthorizeCode, err error) {
	ac = new(AuthorizeCode)
	ac.FromString(code)
	if ac.Key == "" || ac.Signature == "" {
		return nil, errors.New("Key and signature must both be not empty")
	}

	signature := make([]byte, base64.RawStdEncoding.DecodedLen(len(ac.Signature)))
	if _, err := base64.RawStdEncoding.Decode(signature, []byte(ac.Signature)); err != nil {
		return nil, err
	}

	if err := c.Hasher.Compare(signature, []byte(ac.Key)); err != nil {
		// Hash is invalid
		return nil, err
	}

	return ac, nil
}
