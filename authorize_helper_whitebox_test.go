// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsLookbackAddress(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected bool
	}{
		{
			"ShouldReturnTrueIPv4Loopback",
			"127.0.0.1",
			true,
		},
		{
			"ShouldReturnTrueIPv4LoopbackWithPort",
			"127.0.0.1:1230",
			true,
		},
		{
			"ShouldReturnTrueIPv6Loopback",
			"[::1]",
			true,
		},
		{
			"ShouldReturnTrueIPv6LoopbackWithPort",
			"[::1]:1230",
			true,
		}, {
			"ShouldReturnFalse12700255",
			"127.0.0.255",
			false,
		},
		{
			"ShouldReturnFalse12700255WithPort",
			"127.0.0.255:1230",
			false,
		},
		{
			"ShouldReturnFalseInvalidFourthOctet",
			"127.0.0.11230",
			false,
		},
		{
			"ShouldReturnFalseInvalidIPv4",
			"127x0x0x11230",
			false,
		},
		{
			"ShouldReturnFalseInvalidIPv6",
			"[::1]1230",
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, isLoopbackAddress(tc.have))
		})
	}
}
