package fosite

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetRequiredScope(t *testing.T) {
	f := Fosite{MandatoryScope: ""}
	assert.Equal(t, DefaultMandatoryScope, f.GetMandatoryScope())

	f.MandatoryScope = "foo"
	assert.Equal(t, "foo", f.GetMandatoryScope())
}
