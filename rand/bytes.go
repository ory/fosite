package rand

import (
	"crypto/rand"
	"io"

	"github.com/go-errors/errors"
)

// RandomBytes returns n random bytes by reading from crypto/rand.Reader
func RandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return []byte{}, errors.New(err)
	}
	return bytes, nil
}
