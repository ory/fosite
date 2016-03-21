package store

import (
	"github.com/go-errors/errors"
	"github.com/ory-am/common/pkg"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/client"
	"golang.org/x/net/context"
)

type UserRelation struct {
	Username string
	Password string
}

type Store struct {
	Clients        map[string]*client.SecureClient
	AuthorizeCodes map[string]fosite.Requester
	IDSessions     map[string]fosite.Requester
	AccessTokens   map[string]fosite.Requester
	Implicit       map[string]fosite.Requester
	RefreshTokens  map[string]fosite.Requester
	Users          map[string]UserRelation
}

func NewStore() *Store {
	return &Store{
		Clients:        make(map[string]*client.SecureClient),
		AuthorizeCodes: make(map[string]fosite.Requester),
		IDSessions:     make(map[string]fosite.Requester),
		AccessTokens:   make(map[string]fosite.Requester),
		Implicit:       make(map[string]fosite.Requester),
		RefreshTokens:  make(map[string]fosite.Requester),
		Users:          make(map[string]UserRelation),
	}

}

func (s *Store) CreateOpenIDConnectSession(_ context.Context, authorizeCode string, requester fosite.Requester) error {
	s.IDSessions[authorizeCode] = requester
	return nil
}

func (s *Store) GetOpenIDConnectSession(_ context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	cl, ok := s.IDSessions[authorizeCode]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	return cl, nil
}

func (s *Store) DeleteOpenIDConnectSession(_ context.Context, authorizeCode string) error {
	delete(s.IDSessions, authorizeCode)
	return nil
}

func (s *Store) GetClient(id string) (client.Client, error) {
	cl, ok := s.Clients[id]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	return cl, nil
}

func (s *Store) CreateAuthorizeCodeSession(_ context.Context, code string, req fosite.Requester) error {
	s.AuthorizeCodes[code] = req
	return nil
}

func (s *Store) GetAuthorizeCodeSession(_ context.Context, code string, _ interface{}) (fosite.Requester, error) {
	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	return rel, nil
}

func (s *Store) DeleteAuthorizeCodeSession(_ context.Context, code string) error {
	delete(s.AuthorizeCodes, code)
	return nil
}

func (s *Store) CreateAccessTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	s.AccessTokens[signature] = req
	return nil
}

func (s *Store) GetAccessTokenSession(_ context.Context, signature string, _ interface{}) (fosite.Requester, error) {
	rel, ok := s.AccessTokens[signature]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	return rel, nil
}

func (s *Store) DeleteAccessTokenSession(_ context.Context, signature string) error {
	delete(s.AccessTokens, signature)
	return nil
}

func (s *Store) CreateRefreshTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	s.RefreshTokens[signature] = req
	return nil
}

func (s *Store) GetRefreshTokenSession(_ context.Context, signature string, _ interface{}) (fosite.Requester, error) {
	rel, ok := s.RefreshTokens[signature]
	if !ok {
		return nil, pkg.ErrNotFound
	}
	return rel, nil
}

func (s *Store) DeleteRefreshTokenSession(_ context.Context, signature string) error {
	delete(s.RefreshTokens, signature)
	return nil
}

func (s *Store) CreateImplicitAccessTokenSession(_ context.Context, code string, req fosite.Requester) error {
	s.Implicit[code] = req
	return nil
}

func (s *Store) Authenticate(_ context.Context, name string, secret string) error {
	rel, ok := s.Users[name]
	if !ok {
		return pkg.ErrNotFound
	}
	if rel.Password != secret {
		return errors.New("Invalid credentials")
	}
	return nil
}

func (s *Store) PersistAuthorizeCodeGrantSession(ctx context.Context, authorizeCode, accessSignature, refreshSignature string, request fosite.Requester) error {
	if err := s.DeleteAuthorizeCodeSession(ctx, authorizeCode); err != nil {
		return err
	} else if err := s.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return err
	} else if err := s.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return err
	}

	return nil
}
func (s *Store) PersistRefreshTokenGrantSession(ctx context.Context, originalRefreshSignature, accessSignature, refreshSignature string, request fosite.Requester) error {
	if err := s.DeleteRefreshTokenSession(ctx, originalRefreshSignature); err != nil {
		return err
	} else if err := s.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return err
	} else if err := s.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return err
	}

	return nil
}
