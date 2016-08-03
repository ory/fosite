package fosite_test

import (
	"testing"

	. "github.com/ory-am/fosite"
	"github.com/ory-am/fosite/fosite-example/store"
	"github.com/ory-am/fosite/handler/core"
	"github.com/ory-am/fosite/handler/core/explicit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFosite(t *testing.T) {
	f := NewFosite(store.NewStore())
	assert.NotNil(t, f.Store)
	assert.NotNil(t, f.Validators)
	assert.NotNil(t, f.TokenEndpointHandlers)
	assert.NotNil(t, f.Validators)
}

func TestAuthorizeEndpointHandlers(t *testing.T) {
	h := &explicit.AuthorizeExplicitGrantTypeHandler{}
	hs := AuthorizeEndpointHandlers{}
	hs.Append(h)
	assert.Len(t, hs, 1)
	assert.Equal(t, hs[0], h)
}

func TestTokenEndpointHandlers(t *testing.T) {
	h := &explicit.AuthorizeExplicitGrantTypeHandler{}
	hs := TokenEndpointHandlers{}
	hs.Append(h)
	require.Len(t, hs, 1)
	assert.Equal(t, hs[0], h)
}

func TestAuthorizedRequestValidators(t *testing.T) {
	h := &core.CoreValidator{}
	hs := AuthorizedRequestValidators{}
	hs.Append(h)
	require.Len(t, hs, 1)
	assert.Equal(t, hs[0], h)
}
