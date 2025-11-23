// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/golang/mock/mockgen -package rfc8693 -destination storage_mock.go github.com/ory/fosite/handler/rfc8693 RFC8693Storage

package rfc8693
