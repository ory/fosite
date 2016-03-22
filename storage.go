package fosite

import (
	"github.com/ory-am/fosite/client"
)

// Storage defines fosite's minimal storage interface.
type Storage interface {
	client.Storage
}
