package session

import (
	"encoding/json"
	"github.com/go-errors/errors"
	"github.com/ory-am/fosite/auth"
)

// Session defines a authorize flow session which will be persisted and passed to the token endpoint (Authorize Code Flow).
type Session interface {
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

// JSONSession uses json.Marshal and json.Unmarshall to store extra information. It is recommended to use this
// implementation.
type JSONSession struct {
	extra         []byte
	responseTypes []string
	clientID      string
	scopes        []string
	redirectURI   string
	state         string
	signature     string
	ar            *auth.AuthorizeRequest
}

func NewJSONSession(ar *auth.AuthorizeRequest) *JSONSession {
	return &JSONSession{
		ar: ar,
		signature: ar.Code.Signature,
		extra: []byte{},
		responseTypes: ar.Types,
		clientID: ar.Client.GetID(),
		state: ar.State,
		redirectURI: ar.RedirectURI,
	}
}

func (s *JSONSession) SetExtra(extra interface{}) error {
	result, err := json.Marshal(extra)
	if err != nil {
		return errors.New(err)
	}
	s.extra = result
	return nil
}

func (s *JSONSession) WriteExtra(to interface{}) error {
	if err := json.Unmarshal(s.extra, to); err != nil {
		return errors.New(err)
	}
	return nil
}

func (s *JSONSession) GetResponseTypes() []string {
	return s.responseTypes
}

func (s *JSONSession) GetClientID() string {
	return s.clientID
}

func (s *JSONSession) GetScopes() []string {
	return s.scopes
}

func (s *JSONSession) GetRedirectURI() string {
	return s.redirectURI
}

func (s *JSONSession) GetState() string {
	return s.state
}

func (s *JSONSession) GetCodeSignature() string {
	return s.GetCodeSignature()
}