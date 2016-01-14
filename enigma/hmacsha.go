package enigma

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/go-errors/errors"
	"github.com/ory-am/fosite/rand"
	"strings"
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

var b64 = base64.StdEncoding.WithPadding(base64.NoPadding)

// Generate generates a token and a matching signature or returns an error.
// This method implements rfc6819 Section 5.1.4.2.2: Use High Entropy for Secrets.
func (c *HMACSHAEnigma) Generate(secret []byte) (string, string, error) {
	if len(secret) < minimumSecretLength/2 || len(c.GlobalSecret) < minimumSecretLength/2 {
		return "", "", errors.New("Secret or GlobalSecret are not strong enough")
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
	randomBytes, err := rand.RandomBytes(c.AuthCodeEntropy)
	if err != nil {
		return "", "", errors.New(err)
	}

	if len(randomBytes) < c.AuthCodeEntropy {
		return "", "", errors.New("Could not read enough random data for key generation")
	}

	useSecret := append([]byte{}, c.GlobalSecret...)
	mac := hmac.New(sha256.New, append(useSecret, secret...))
	_, err = mac.Write(randomBytes)
	if err != nil {
		return "", "", errors.New(err)
	}
	signature := mac.Sum([]byte{})

	token := fmt.Sprintf("%s.%s", b64.EncodeToString(randomBytes), b64.EncodeToString(signature))
	return token, signature, nil
}

// Validate validates a token and returns its signature or an error if the token is not valid.
func (c *HMACSHAEnigma) Validate(secret []byte, token string) (string, error) {
	split := strings.Split(token, ".")
	if len(split) != 2 {
		return "", errors.New("Key and signature must both be set")
	}

	signature := split[0]
	key := split[1]
	if key == "" || signature == "" {
		return "", errors.New("Key and signature must both be set")
	}

	decodedSignature, err := b64.DecodeString(signature)
	if err != nil {
		return "", err
	}

	decodedKey, err := b64.DecodeString(key)
	if err != nil {
		return "", err
	}

	useSecret := append([]byte{}, c.GlobalSecret...)
	mac := hmac.New(sha256.New, append(useSecret, secret...))
	_, err = mac.Write(decodedKey)
	if err != nil {
		return "", errors.New(err)
	}

	if !hmac.Equal(decodedSignature, mac.Sum([]byte{})) {
		// Hash is invalid
		return "", errors.New("Key and signature do not match")
	}

	return signature, nil
}
