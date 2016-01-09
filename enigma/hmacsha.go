package enigma

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"github.com/go-errors/errors"
	"github.com/ory-am/fosite/rand"
)

// HMACSHAEnigma is the default implementation for generating and validating challenges. It uses HMAC-SHA256 to
// generate and validate challenges.
type HMACSHAEnigma struct {
	AuthCodeEntropy int
	GlobalSecret    []byte
}

// key should be at least 256 bit long, making it
const minimumEntropy = 32

// the secrets (client and global) should each have at least 16 characters making it harder to guess them
const minimumSecretLength = 32

// GenerateAuthorizeCode generates a new authorize code or returns an error. set secret
// This method implements rfc6819 Section 5.1.4.2.2: Use High Entropy for Secrets.
func (c *HMACSHAEnigma) GenerateChallenge(secret []byte) (*Challenge, error) {
	if len(secret) < minimumSecretLength/2 || len(c.GlobalSecret) < minimumSecretLength/2 {
		return nil, errors.New("Secret or GlobalSecret are not strong enough")
	}

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
		return nil, errors.New(err)
	}

	if len(randomBytes) < c.AuthCodeEntropy {
		return nil, errors.New("Could not read enough random data for key generation")
	}

	useSecret := append([]byte{}, c.GlobalSecret...)
	mac := hmac.New(sha256.New, append(useSecret, secret...))
	_, err = mac.Write(randomBytes)
	if err != nil {
		return nil, errors.New(err)
	}
	signature := mac.Sum([]byte{})

	encodedKey := make([]byte, base64.StdEncoding.EncodedLen(c.AuthCodeEntropy))
	base64.StdEncoding.Encode(encodedKey, randomBytes)
	encodedKey = bytes.Trim(encodedKey, "\x00")

	encodedSignature := make([]byte, base64.StdEncoding.EncodedLen(len(signature)))
	base64.StdEncoding.Encode(encodedSignature, signature)
	encodedSignature = bytes.Trim(encodedSignature, "\x00")

	return &Challenge{
		Key:       string(encodedKey),
		Signature: string(encodedSignature),
	}, nil
}

// ValidateAuthorizeCodeSignature returns an AuthorizeCode, if the code argument is a valid authorize code
// and the signature matches the key.
func (c *HMACSHAEnigma) ValidateChallenge(secret []byte, t *Challenge) (err error) {
	if t.Key == "" || t.Signature == "" {
		return errors.New("Key and signature must both be not empty")
	}

	key := make([]byte, base64.StdEncoding.DecodedLen(len(t.Key)))
	if _, err := base64.StdEncoding.Decode(key, []byte(t.Signature)); err != nil {
		return err
	}

	signature := make([]byte, base64.StdEncoding.DecodedLen(len(t.Signature)))
	if _, err := base64.StdEncoding.Decode(signature, []byte(t.Signature)); err != nil {
		return err
	}

	useSecret := append([]byte{}, c.GlobalSecret...)
	mac := hmac.New(sha256.New, append(useSecret, secret...))
	_, err = mac.Write(key)
	if err != nil {
		return errors.New(err)
	}

	if !hmac.Equal(signature, mac.Sum([]byte{})) {
		// Hash is invalid
		return errors.New("Key and signature do not match")
	}

	return nil
}
