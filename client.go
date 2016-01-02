package fosite

import "github.com/ory-am/fosite/hash"

// Client represents a client or an app.
type Client interface {
	// GetID returns the client ID.
	GetID() string

	// CompareSecret compares a secret with the stored one (e.g. a hash) and returns true if
	// the secrets match.
	CompareSecretWith(secret string) bool

	// Returns the client's allowed redirect URIs.
	GetRedirectURIs() []string
}

// DefaultClient is a simple default implementation of the Client interface.
type SecureClient struct {
	ID           string      `json:"id"`
	Secret       string      `json:"secret"`
	RedirectURIs []string    `json:"redirectURIs"`
	Hasher       hash.Hasher `json:"-"`
}

func (c *SecureClient) GetID() string {
	return c.ID
}

func (c *SecureClient) CompareSecretWith(secret string) bool {
	return c.Hasher.Compare([]byte(c.Secret), []byte(secret)) == nil
}

func (c *SecureClient) GetRedirectURIs() []string {
	return c.RedirectURIs
}
