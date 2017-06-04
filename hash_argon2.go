package fosite

import (
	"github.com/lhecker/argon2"
	"github.com/pkg/errors"
)

// Argon2 implements the Hasher interface by using github.com/lhecker/Argon2.
//
// Issues related to building and developing on Windows:
//   For Argon2 Hasher to work on Windows you will require a compatible CGO environment.
//   for 32-bit Windows:
// 	* Install [MinGW for x86](https://sourceforge.net/projects/mingw/files/latest/download?source=files)
//	* Add `C:\MinGW\bin` to path
//	* Select and install `gcc-core`
//	* Select and install `gcc-g++`
//	* Build successfully!
//   For 64-bit Windows:
// 	* Install [Cygwin]()
//	* Add `C:\cygwin64\bin` to path
// 	* Select and Install `x86_64-w64-mingw32-gcc-core`
// 	* Select and Install `x86_64-w64-mingw32-gcc-g++`
//	* Change all file names in `C:\cygwin64\bin` by removing `x86_64-w64-mingw32-` which is prepended to all files we need to use..
//	* Build successfully!
type Argon2 struct {
	Config argon2.Config
}

// Compare compares data with an Argon2 hash and returns an error
// if the two do not match.
func (a *Argon2) Compare(hash, data []byte) error {
	ok, err := argon2.VerifyEncoded(data, hash)
	if err != nil {
		return errors.WithStack(err)
	}
	if !ok {
		return ErrRequestUnauthorized
	}
	return nil
}

// Hash creates a Argon2 hash from data or returns an error.
// The salt is automatically generated based on the length of the Salt as specified by Config.SaltLength
func (a *Argon2) Hash(data []byte) ([]byte, error) {
	s, err := a.Config.HashEncoded(data)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return s, nil
}
