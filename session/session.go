package session

import (
	"encoding/json"
	"github.com/go-errors/errors"
	"github.com/ory-am/fosite"
)

// Session defines a authorize flow session which will be persisted and passed to the token endpoint (Authorize Code Flow).
type AuthorizeSession interface {
	// SetExtra sets extra information that you want to be persisted. Ignore this if you have
	// your own session management or do not need additional persistent states.
	SetExtra(extra interface{}) error

	// WriteExtra write the extra information back to a struct pointer.
	WriteExtra(to interface{}) error

	// GetResponseTypes returns the response types for this authorize session.
	GetResponseTypes() []string

	// GetResponseTypes returns the client id (audience) for this authorize session.
	GetClientID() string

	// GetResponseTypes returns the scope for this authorize session.
	GetScopes() []string

	// GetUser returns the user for this authorize session.
	GetUserID() string

	// GetResponseTypes returns the redirect_uri for this authorize session.
	GetRedirectURI() string

	// GetResponseTypes returns the state for this authorize session.
	GetState() string

	// GetResponseTypes returns the code's signature for this authorize session.
	// Once persisted, you lose access to the code's key which is required for a valid code.
	// This keeps you safe from a wide range attack vectors regarding your database with SQL injection being
	// the most popular.
	GetCodeSignature() string
}

// defaultSession uses json.Marshal and json.Unmarshall to store extra information. It is recommended to use this
// implementation.
type defaultSession struct {
	extra         []byte
	responseTypes []string
	clientID      string
	scopes        []string
	redirectURI   string
	state         string
	signature     string
	userID        string
	ar            *fosite.AuthorizeRequest
}

func NewAuthorizeSession(ar *fosite.AuthorizeRequest, userID string) AuthorizeSession {
	return &defaultSession{
		ar:            ar,
		signature:     ar.Code.Signature,
		extra:         []byte{},
		responseTypes: ar.ResponseTypes,
		clientID:      ar.Client.GetID(),
		state:         ar.State,
		scopes:        ar.Scopes,
		redirectURI:   ar.RedirectURI,
		userID:        userID,
	}
}

func (s *defaultSession) SetExtra(extra interface{}) error {
	result, err := json.Marshal(extra)
	if err != nil {
		return errors.New(err)
	}
	s.extra = result
	return nil
}

func (s *defaultSession) WriteExtra(to interface{}) error {
	if err := json.Unmarshal(s.extra, to); err != nil {
		return errors.New(err)
	}
	return nil
}

func (s *defaultSession) GetResponseTypes() []string {
	return s.responseTypes
}

func (s *defaultSession) GetClientID() string {
	return s.clientID
}

func (s *defaultSession) GetScopes() []string {
	return s.scopes
}

func (s *defaultSession) GetRedirectURI() string {
	return s.redirectURI
}

func (s *defaultSession) GetState() string {
	return s.state
}

func (s *defaultSession) GetCodeSignature() string {
	return s.signature
}

func (s *defaultSession) GetUserID() string {
	return s.userID
}
