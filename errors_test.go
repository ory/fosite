package fosite

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddDebug(t *testing.T) {
	err := ErrRevokationClientMismatch.WithDebug("debug")
	assert.NotEqual(t, err, ErrRevokationClientMismatch)
	assert.Empty(t, ErrRevokationClientMismatch.Debug)
	assert.NotEmpty(t, err.Debug)
}
