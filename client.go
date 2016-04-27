package fosite

// Client represents a client or an app.
type Client interface {
	// GetID returns the client ID.
	GetID() string

	// GetHashedSecret returns the hashed secret as it is stored in the store.
	GetHashedSecret() []byte

	// Returns the client's allowed redirect URIs.
	GetRedirectURIs() []string
}

// DefaultClient is a simple default implementation of the Client interface.
type DefaultClient struct {
	ID           string   `json:"id"`
	Secret       []byte   `json:"secret"`
	RedirectURIs []string `json:"redirectURIs"`
}

func (c *DefaultClient) GetID() string {
	return c.ID
}

func (c *DefaultClient) GetRedirectURIs() []string {
	return c.RedirectURIs
}

func (c *DefaultClient) GetHashedSecret() []byte {
	return c.Secret
}
