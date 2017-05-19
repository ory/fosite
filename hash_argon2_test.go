package fosite

import (
	"testing"

	"github.com/lhecker/argon2"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
)

// TestArgon2Hash ensures that a hash is returned from the Argon2 Hasher
func TestArgon2Hash(t *testing.T) {
	h := &Argon2{
		Config: argon2.DefaultConfig(),
	}
	password := []byte("foo")
	hash, err := h.Hash(password)
	assert.Nil(t, err)
	assert.NotNil(t, hash)
	assert.NotEqual(t, hash, password)
}

// TestArgon2HashLibErr purposely causes the underlying argon2 lib to error to ensure it is reported up the stack
func TestArgon2HashLibErr(t *testing.T) {
	h := &Argon2{
		Config: argon2.DefaultConfig(),
	}
	h.Config.MemoryCost = 1
	password := []byte("foo")
	hash, err := h.Hash(password)
	assert.Empty(t, hash)
	assert.NotNil(t, err)
	assert.NotEqual(t, hash, password)
}

// TestArgon2CompareEquals ensures a password can be verified successfully when decoded
func TestArgon2CompareEquals(t *testing.T) {
	h := &Argon2{
		Config: argon2.DefaultConfig(),
	}
	password := []byte("foo")
	hash, err := h.Hash(password)
	assert.Nil(t, err)
	assert.NotNil(t, hash)
	err = h.Compare(hash, password)
	assert.Nil(t, err)
}

// TestArgon2CompareEquals ensures a compare errors when a presented clear text password does not match the original
func TestArgon2CompareDifferent(t *testing.T) {
	h := &Argon2{
		Config: argon2.DefaultConfig(),
	}
	password := []byte("foo")
	hash, err := h.Hash(password)
	assert.Nil(t, err)
	assert.NotNil(t, hash)
	err = h.Compare(hash, []byte(uuid.NewRandom()))
	assert.NotNil(t, err)
}

// TestArgon2HashLibErr purposely causes the underlying argon2 lib to error to ensure it is reported up the stack
func TestArgon2CompareLibErr(t *testing.T) {
	h := &Argon2{
		Config: argon2.DefaultConfig(),
	}
	h.Config.MemoryCost = 1
	password := []byte("foo")
	hash, err := h.Hash(password)
	assert.Empty(t, hash)
	assert.NotNil(t, err)
	err = h.Compare(hash, []byte(uuid.NewRandom()))
	assert.NotNil(t, err)
}
