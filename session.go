package fosite

import (
	"bytes"
	"encoding/gob"
	"github.com/go-errors/errors"
	"github.com/ory-am/fosite/generator"
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

// defaultSession uses gob.Encode and gob.Decode to store extra information. It is recommended to use this
// implementation.
type sqlSession struct {
	extra         []byte
	responseTypes []string
	clientID      string
	scopes        []string
	redirectURI   string
	state         string
	code          *generator.Token
	userID        string
	ar            *AuthorizeRequest
}

// NewAuthorizeSessionSQL creates a new authorize session and uses gob.Encode and gob.Decode to store extra information.
// It is recommended to use this implementation.
func NewAuthorizeSessionSQL(ar *AuthorizeRequest, userID string) AuthorizeSession {
	var uri string
	if ar.RedirectURI != nil {
		uri = ar.RedirectURI.String()
	}
	return &sqlSession{
		ar:            ar,
		code:          ar.Code,
		extra:         []byte{},
		responseTypes: ar.ResponseTypes,
		clientID:      ar.Client.GetID(),
		state:         ar.State,
		scopes:        ar.Scopes,
		redirectURI:   uri,
		userID:        userID,
	}
}

func (s *sqlSession) SetExtra(extra interface{}) error {
	var network bytes.Buffer
	if err := gob.NewEncoder(&network).Encode(extra); err != nil {
		return errors.New(err)
	}
	s.extra = network.Bytes()
	return nil
}

func (s *sqlSession) WriteExtra(to interface{}) error {
	if err := gob.NewDecoder(bytes.NewReader(s.extra)).Decode(to); err != nil {
		return errors.New(err)
	}
	return nil
}

func (s *sqlSession) GetResponseTypes() []string {
	return s.responseTypes
}

func (s *sqlSession) GetClientID() string {
	return s.clientID
}

func (s *sqlSession) GetScopes() []string {
	return s.scopes
}

func (s *sqlSession) GetRedirectURI() string {
	return s.redirectURI
}

func (s *sqlSession) GetState() string {
	return s.state
}

func (s *sqlSession) GetCodeSignature() string {
	return s.code.Signature
}

func (s *sqlSession) GetUserID() string {
	return s.userID
}
