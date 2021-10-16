// par packages the pushed authorization request handlers and storage
package par

import (
	"context"

	"github.com/ory/fosite"
)

// PARStorage holds information needed to store and retrieve PAR context.
type PARStorage interface {
	// CreatePARSession stores the pushed authorization request context. The requestURI is used to derive the key.
	CreatePARSession(ctx context.Context, requestURI string, request fosite.AuthorizeRequester) error
	// GetPARSession gets the push authorization request context. If the request is nil, a new request object
	// is created. Otherwise, the same object is updated.
	GetPARSession(ctx context.Context, requestURI string, request fosite.AuthorizeRequester) error
	// DeletePARSession deletes the context.
	DeletePARSession(ctx context.Context, requestURI string) (err error)
}
