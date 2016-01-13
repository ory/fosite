package client

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
type SecureClient struct {
	ID           string   `json:"id"`
	Secret       []byte   `json:"secret"`
	RedirectURIs []string `json:"redirectURIs"`
}

func (c *SecureClient) GetID() string {
	return c.ID
}

func (c *SecureClient) GetRedirectURIs() []string {
	return c.RedirectURIs
}

func (c *SecureClient) GetHashedSecret() []byte {
	return c.Secret
}
