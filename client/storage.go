package client

// Storage defines the storage interface for clients.
type Storage interface {
	// GetClient loads the client by its ID or returns an error
	// if the client does not exist or another error occurred.
	GetClient(id string) (Client, error)
}
