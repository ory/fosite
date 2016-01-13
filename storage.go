package fosite

import (
	. "github.com/ory-am/fosite/client"
)

// Storage defines fosite's minimal storage interface.
type Storage interface {
	// GetClient loads the client by its ID or returns an error
	// if the client does not exist or another error occurred.
	GetClient(id string) (Client, error)
}
