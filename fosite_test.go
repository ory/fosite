// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/par"
)

func TestAuthorizeEndpointHandlers(t *testing.T) {
	h := &oauth2.AuthorizeExplicitGrantHandler{}
	hs := AuthorizeEndpointHandlers{}
	hs.Append(h)
	hs.Append(h)
	hs.Append(&oauth2.AuthorizeExplicitGrantHandler{})
	assert.Len(t, hs, 1)
	assert.Equal(t, hs[0], h)
}

func TestTokenEndpointHandlers(t *testing.T) {
	h := &oauth2.AuthorizeExplicitGrantHandler{}
	hs := TokenEndpointHandlers{}
	hs.Append(h)
	hs.Append(h)
	// do some crazy type things and make sure dupe detection works
	var f interface{} = &oauth2.AuthorizeExplicitGrantHandler{}
	hs.Append(&oauth2.AuthorizeExplicitGrantHandler{})
	hs.Append(f.(TokenEndpointHandler))
	require.Len(t, hs, 1)
	assert.Equal(t, hs[0], h)
}

func TestAuthorizedRequestValidators(t *testing.T) {
	h := &oauth2.CoreValidator{}
	hs := TokenIntrospectionHandlers{}
	hs.Append(h)
	hs.Append(h)
	hs.Append(&oauth2.CoreValidator{})
	require.Len(t, hs, 1)
	assert.Equal(t, hs[0], h)
}

func TestPushedAuthorizedRequestHandlers(t *testing.T) {
	h := &par.PushedAuthorizeHandler{}
	hs := PushedAuthorizeEndpointHandlers{}
	hs.Append(h)
	hs.Append(h)
	require.Len(t, hs, 1)
	assert.Equal(t, hs[0], h)
}

func TestMinParameterEntropy(t *testing.T) {
	f := Fosite{Config: new(Config)}
	assert.Equal(t, MinParameterEntropy, f.GetMinParameterEntropy(context.Background()))

	f = Fosite{Config: &Config{MinParameterEntropy: 42}}
	assert.Equal(t, 42, f.GetMinParameterEntropy(context.Background()))
}
