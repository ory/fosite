package fosite

import "context"

// ClientManager defines the (persistent) manager interface for clients.
type ClientManager interface {
	// GetClient loads the client by its ID or returns an error
	// if the client does not exist or another error occurred.
	GetClient(ctx context.Context, id string) (Client, error)
}
