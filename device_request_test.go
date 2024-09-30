// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeviceRequest(t *testing.T) {
	r := NewDeviceRequest()
	r.Client = &DefaultClient{}
	r.SetRequestedScopes([]string{"17", "42"})
	assert.True(t, r.GetRequestedScopes().Has("17", "42"))
	assert.Equal(t, r.Client, r.GetClient())
}
