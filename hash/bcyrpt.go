package hash

import (
	"github.com/go-errors/errors"
	"golang.org/x/crypto/bcrypt"
)

// BCrypt implements the Hasher interface by providing BCrypt hashing.
type BCrypt struct {
	WorkFactor int
}

func (b *BCrypt) Hash(data []byte) ([]byte, error) {
	s, err := bcrypt.GenerateFromPassword(data, b.WorkFactor)
	if err != nil {
		return nil, errors.New(err)
	}
	return s, nil
}

func (b *BCrypt) Compare(hash, data []byte) error {
	if err := bcrypt.CompareHashAndPassword(hash, data); err != nil {
		return errors.New(err)
	}
	return nil
}
