package fosite

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/go-errors/errors"
	native "errors"
)

func TestErrorToRFC6749(t *testing.T) {
	assert.Equal(t, errInvalidError, ErrorToRFC6749(errors.New("")).Name)
	assert.Equal(t, errInvalidError, ErrorToRFC6749(native.New("")).Name)

	assert.Equal(t, errInvalidRequestName, ErrorToRFC6749(errors.New(ErrInvalidRequest)).Name)
	assert.Equal(t, errUnauthorizedClientName, ErrorToRFC6749(errors.New(ErrUnauthorizedClient)).Name)
	assert.Equal(t, errAccessDeniedName, ErrorToRFC6749(errors.New(ErrAccessDenied)).Name)
	assert.Equal(t, errUnsupportedResponseTypeName, ErrorToRFC6749(errors.New(ErrUnsupportedResponseType)).Name)
	assert.Equal(t, errInvalidScopeName, ErrorToRFC6749(errors.New(ErrInvalidScope)).Name)
	assert.Equal(t, errServerErrorName, ErrorToRFC6749(errors.New(ErrServerError)).Name)
	assert.Equal(t, errTemporarilyUnavailableName, ErrorToRFC6749(errors.New(ErrTemporarilyUnavailable)).Name)
	assert.Equal(t, errUnsupportedGrantTypeName, ErrorToRFC6749(errors.New(ErrUnsupportedGrantType)).Name)
	assert.Equal(t, errInvalidGrantName, ErrorToRFC6749(errors.New(ErrInvalidGrant)).Name)
	assert.Equal(t, errInvalidClientName, ErrorToRFC6749(errors.New(ErrInvalidClient)).Name)
}