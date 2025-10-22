// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

// Storage defines fosite's minimal storage interface.
type Storage interface {
	ClientManager() ClientManager
}
