package internal

import (
	"github.com/go-errors/errors"
	"github.com/ory-am/common/pkg"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
)

type UserRelation struct {
	Username string
	Password string
}

type Store struct {
	Clients        map[string]client.Client
	AuthorizeCodes map[string]fosite.Requester
	AccessTokens   map[string]fosite.Requester
	Implicit       map[string]fosite.Requester
	RefreshTokens  map[string]fosite.Requester
	Users          map[string]UserRelation
}

func (s *Store) GetClient(id string) (client.Client, error) {
	cl, ok := s.Clients[id]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	return cl, nil
}

func (s *Store) CreateAuthorizeCodeSession(code string, req fosite.Requester) error {
	s.AuthorizeCodes[code] = req
	return nil
}

func (s *Store) GetAuthorizeCodeSession(code string, _ interface{}) (fosite.Requester, error) {
	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	return rel, nil
}

func (s *Store) DeleteAuthorizeCodeSession(code string) error {
	delete(s.AuthorizeCodes, code)
	return nil
}

func (s *Store) CreateAccessTokenSession(signature string, req fosite.Requester) error {
	s.AccessTokens[signature] = req
	return nil
}

func (s *Store) GetAccessTokenSession(signature string, _ interface{}) (fosite.Requester, error) {
	rel, ok := s.AccessTokens[signature]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	return rel, nil
}

func (s *Store) DeleteAccessTokenSession(signature string) error {
	delete(s.AccessTokens, signature)
	return nil
}

func (s *Store) CreateRefreshTokenSession(signature string, req fosite.Requester) error {
	s.RefreshTokens[signature] = req
	return nil
}

func (s *Store) GetRefreshTokenSession(signature string, _ interface{}) (fosite.Requester, error) {
	rel, ok := s.RefreshTokens[signature]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	return rel, nil
}

func (s *Store) DeleteRefreshTokenSession(signature string) error {
	delete(s.RefreshTokens, signature)
	return nil
}

func (s *Store) CreateImplicitAccessTokenSession(code string, req fosite.Requester) error {
	s.Implicit[code] = req
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
