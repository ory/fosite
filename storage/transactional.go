// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package storage

import "context"

// A storage provider that has support for transactions should implement this
// interface to ensure atomicity for certain flows that require transactional
// semantics. When atomicity is required, Fosite will group calls to the storage
// provider in a function and passes that to Transaction.  Implementations are
// expected to execute these calls in a transactional manner. Typically, a
// handle to the transaction will be stored in the context.
//
// Implementations should rollback (or retry) the transaction if the callback
// returns an error.
type Transactional interface {
	Transaction(context.Context, func(context.Context) error) error
}

func MaybeTransaction(ctx context.Context, storage any, f func(context.Context) error) error {
	if tx, ok := storage.(Transactional); ok {
		return tx.Transaction(ctx, f)
	}
	return f(ctx)
}
