package fosite

import (
	native "errors"
	"testing"

	"github.com/go-errors/errors"
	"github.com/stretchr/testify/assert"
)

func TestErrorToRFC6749(t *testing.T) {
	assert.Equal(t, errInvalidError, ErrorToRFC6749Error(errors.New("")).Name)
	assert.Equal(t, errInvalidError, ErrorToRFC6749Error(native.New("")).Name)

	assert.Equal(t, errInvalidRequestName, ErrorToRFC6749Error(errors.New(ErrInvalidRequest)).Name)
	assert.Equal(t, errUnauthorizedClientName, ErrorToRFC6749Error(errors.New(ErrUnauthorizedClient)).Name)
	assert.Equal(t, errAccessDeniedName, ErrorToRFC6749Error(errors.New(ErrAccessDenied)).Name)
	assert.Equal(t, errUnsupportedResponseTypeName, ErrorToRFC6749Error(errors.New(ErrUnsupportedResponseType)).Name)
	assert.Equal(t, errInvalidScopeName, ErrorToRFC6749Error(errors.New(ErrInvalidScope)).Name)
	assert.Equal(t, errServerErrorName, ErrorToRFC6749Error(errors.New(ErrServerError)).Name)
	assert.Equal(t, errTemporarilyUnavailableName, ErrorToRFC6749Error(errors.New(ErrTemporarilyUnavailable)).Name)
	assert.Equal(t, errUnsupportedGrantTypeName, ErrorToRFC6749Error(errors.New(ErrUnsupportedGrantType)).Name)
	assert.Equal(t, errInvalidGrantName, ErrorToRFC6749Error(errors.New(ErrInvalidGrant)).Name)
	assert.Equal(t, errInvalidClientName, ErrorToRFC6749Error(errors.New(ErrInvalidClient)).Name)
	assert.Equal(t, errInvalidState, ErrorToRFC6749Error(errors.New(ErrInvalidState)).Name)
}
