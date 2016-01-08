package rand

import (
	"crypto/rand"
	"github.com/go-errors/errors"
)

// RandomBytes returns n random bytes by reading from crypto/rand.Reader
func RandomBytes(n, tries int) ([]byte, error) {
	bytes := make([]byte, n)

	var z int
	var err error
	for i := 0; i < tries; i++ {
		z, err = rand.Reader.Read(bytes)
		if err != nil {
			return nil, errors.Wrap(err, 0)
		}
	}
	if z < n {
		return nil, errors.Errorf("Could not read enough data with %d tries", tries)
	}

	return bytes, nil
}
