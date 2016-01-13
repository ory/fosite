package rand

import (
	"crypto/rand"
)

// RandomBytes returns n random bytes by reading from crypto/rand.Reader
func RandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	_, err := rand.Reader.Read(bytes)
	if err != nil {
		return []byte{}, err
	}
	return bytes, nil
}
