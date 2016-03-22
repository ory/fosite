package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeaderToMap(t *testing.T) {
	header := &Header{
		Extra: map[string]interface{}{
			"foo": "bar",
			"alg": "foo",
			"typ": "foo",
		},
	}
	assert.Equal(t, map[string]interface{}{
		"foo": "bar",
	}, header.ToMap())
}
