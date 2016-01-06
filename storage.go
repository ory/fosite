package fosite

import (
	. "github.com/ory-am/fosite/client"
)

// Storage defines fosite's minimal storage interface.
type Storage interface {
	// GetClient loads the client by its ID or returns an error
	// if the client does not exist or another error occurred.
	GetClient(id string) (Client, error)

	// StoreAuthorizeSession persists an authorize request session in the store.
	StoreAuthorizeSession(session *AuthorizeSession) error

	// GetAuthorizeSession finds an authorize request session in the store by the code signature.
	GetAuthorizeSession(signature string, session *AuthorizeSession) error

	// SaveAuthorize saves authorize data.
	// StoreAuthorizeRequest(*AuthorizeData) error

	// LoadAuthorize looks up AuthorizeData by a code.
	// Client information MUST be loaded together.
	// Optionally can return error if expired.
	// LoadAuthorize(code string) (*AuthorizeData, error)

	// RemoveAuthorize revokes or deletes the authorization code.
	// RemoveAuthorize(code string) error

	// SaveAccess writes AccessData.
	// If RefreshToken is not blank, it must save in a way that can be loaded using LoadRefresh.
	// SaveAccess(*AccessData) error

	// LoadAccess retrieves access data by token. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	// LoadAccess(token string) (*AccessData, error)

	// RemoveAccess revokes or deletes an AccessData.
	// RemoveAccess(token string) error

	// LoadRefresh retrieves refresh AccessData. Client information MUST be loaded together.
	// AuthorizeData and AccessData DON'T NEED to be loaded if not easily available.
	// Optionally can return error if expired.
	// LoadRefresh(token string) (*AccessData, error)

	// RemoveRefresh revokes or deletes refresh AccessData.
	// RemoveRefresh(token string) error
}
