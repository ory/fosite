package internal

import (
	"github.com/go-errors/errors"
	"github.com/ory-am/common/pkg"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
	core "github.com/ory-am/fosite/handler/core"
)

type AuthorizeCodesRelation struct {
	request fosite.AuthorizeRequester
	session *core.AuthorizeSession
}

type AccessRelation struct {
	access  fosite.AccessRequester
	session *core.TokenSession
}

type UserRelation struct {
	Username string
	Password string
}

type Store struct {
	Clients        map[string]client.Client
	AuthorizeCodes map[string]AuthorizeCodesRelation
	AccessTokens   map[string]AccessRelation
	Implicit       map[string]AuthorizeCodesRelation
	RefreshTokens  map[string]AccessRelation
	Users          map[string]UserRelation
}

func NewStore() *Store {
	return &Store{
		Clients:        map[string]client.Client{},
		AuthorizeCodes: map[string]AuthorizeCodesRelation{},
		Implicit:       map[string]AuthorizeCodesRelation{},
		AccessTokens:   map[string]AccessRelation{},
		RefreshTokens:  map[string]AccessRelation{},
		Users:          map[string]UserRelation{},
	}
}

func (s *Store) GetClient(id string) (client.Client, error) {
	cl, ok := s.Clients[id]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	return cl, nil
}

func (s *Store) CreateAuthorizeCodeSession(code string, ar fosite.AuthorizeRequester, sess *core.AuthorizeSession) error {
	s.AuthorizeCodes[code] = AuthorizeCodesRelation{request: ar, session: sess}
	return nil
}

func (s *Store) GetAuthorizeCodeSession(code string, sess *core.AuthorizeSession) (fosite.AuthorizeRequester, error) {
	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	sess = rel.session
	return rel.request, nil
}

func (s *Store) DeleteAuthorizeCodeSession(code string) error {
	delete(s.AuthorizeCodes, code)
	return nil
}

func (s *Store) CreateAccessTokenSession(signature string, access fosite.AccessRequester, session *core.TokenSession) error {
	s.AccessTokens[signature] = AccessRelation{access: access, session: session}
	return nil
}

func (s *Store) GetAccessTokenSession(signature string, session *core.TokenSession) (fosite.AccessRequester, error) {
	rel, ok := s.AccessTokens[signature]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	session = rel.session
	return rel.access, nil
}

func (s *Store) DeleteAccessTokenSession(signature string) error {
	delete(s.AccessTokens, signature)
	return nil
}

func (s *Store) CreateRefreshTokenSession(signature string, access fosite.AccessRequester, session *core.TokenSession) error {
	s.RefreshTokens[signature] = AccessRelation{access: access, session: session}
	return nil
}

func (s *Store) GetRefreshTokenSession(signature string, session *core.TokenSession) (fosite.AccessRequester, error) {
	rel, ok := s.RefreshTokens[signature]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	session = rel.session
	return rel.access, nil
}

func (s *Store) DeleteRefreshTokenSession(signature string) error {
	delete(s.RefreshTokens, signature)
	return nil
}

func (s *Store) CreateImplicitAccessTokenSession(code string, ar fosite.AuthorizeRequester, sess *core.AuthorizeSession) error {
	s.Implicit[code] = AuthorizeCodesRelation{request: ar, session: sess}
	return nil
}

func (s *Store) DoCredentialsAuthenticate(name string, secret string) error {
	rel, ok := s.Users[name]
	if !ok {
		return pkg.ErrNotFound
	}
	if rel.Password != secret {
		return errors.New("Invalid credentials")
	}
	return nil
}
