package store

import (
	"github.com/ory-am/fosite"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

type UserRelation struct {
	Username string
	Password string
}

type Store struct {
	Clients        map[string]*fosite.DefaultClient
	AuthorizeCodes map[string]fosite.Requester
	IDSessions     map[string]fosite.Requester
	AccessTokens   map[string]fosite.Requester
	Implicit       map[string]fosite.Requester
	RefreshTokens  map[string]fosite.Requester
	Users          map[string]UserRelation
}

func NewStore() *Store {
	return &Store{
		Clients:        make(map[string]*fosite.DefaultClient),
		AuthorizeCodes: make(map[string]fosite.Requester),
		IDSessions:     make(map[string]fosite.Requester),
		AccessTokens:   make(map[string]fosite.Requester),
		Implicit:       make(map[string]fosite.Requester),
		RefreshTokens:  make(map[string]fosite.Requester),
		Users:          make(map[string]UserRelation),
	}

}

func (s *Store) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (context.Context, error) {
	s.IDSessions[authorizeCode] = requester
	return ctx, nil
}

func (s *Store) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (context.Context, fosite.Requester, error) {
	cl, ok := s.IDSessions[authorizeCode]
	if !ok {
		return ctx, nil, fosite.ErrNotFound
	}
	return ctx, cl, nil
}

func (s *Store) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) (context.Context, error) {
	delete(s.IDSessions, authorizeCode)
	return ctx, nil
}

func (s *Store) GetClient(id string) (fosite.Client, error) {
	cl, ok := s.Clients[id]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return cl, nil
}

func (s *Store) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) (context.Context, error) {
	s.AuthorizeCodes[code] = req
	return ctx, nil
}

func (s *Store) GetAuthorizeCodeSession(ctx context.Context, code string, _ interface{}) (context.Context, fosite.Requester, error) {
	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return ctx, nil, fosite.ErrNotFound
	}
	return ctx, rel, nil
}

func (s *Store) DeleteAuthorizeCodeSession(ctx context.Context, code string) (context.Context, error) {
	delete(s.AuthorizeCodes, code)
	return ctx, nil
}

func (s *Store) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) (context.Context, error) {
	s.AccessTokens[signature] = req
	return ctx, nil
}

func (s *Store) GetAccessTokenSession(ctx context.Context, signature string, _ interface{}) (context.Context, fosite.Requester, error) {
	rel, ok := s.AccessTokens[signature]
	if !ok {
		return ctx, nil, fosite.ErrNotFound
	}
	return ctx, rel, nil
}

func (s *Store) DeleteAccessTokenSession(ctx context.Context, signature string) (context.Context, error) {
	delete(s.AccessTokens, signature)
	return ctx, nil
}

func (s *Store) CreateRefreshTokenSession(ctx context.Context, signature string, req fosite.Requester) (context.Context, error) {
	s.RefreshTokens[signature] = req
	return ctx, nil
}

func (s *Store) GetRefreshTokenSession(ctx context.Context, signature string, _ interface{}) (context.Context, fosite.Requester, error) {
	rel, ok := s.RefreshTokens[signature]
	if !ok {
		return ctx, nil, fosite.ErrNotFound
	}
	return ctx, rel, nil
}

func (s *Store) DeleteRefreshTokenSession(ctx context.Context, signature string) (context.Context, error) {
	delete(s.RefreshTokens, signature)
	return ctx, nil
}

func (s *Store) CreateImplicitAccessTokenSession(ctx context.Context, code string, req fosite.Requester) (context.Context, error) {
	s.Implicit[code] = req
	return ctx, nil
}

func (s *Store) Authenticate(ctx context.Context, name string, secret string) (context.Context, error) {
	rel, ok := s.Users[name]
	if !ok {
		return ctx, fosite.ErrNotFound
	}
	if rel.Password != secret {
		return ctx, errors.New("Invalid credentials")
	}
	return ctx, nil
}

func (s *Store) PersistAuthorizeCodeGrantSession(ctx context.Context, authorizeCode, accessSignature, refreshSignature string, request fosite.Requester) (context.Context, error) {
	var err error
	if ctx, err = s.DeleteAuthorizeCodeSession(ctx, authorizeCode); err != nil {
		return ctx, err
	} else if ctx, err = s.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return ctx, err
	} else if refreshSignature == "" {
		return ctx, nil
	} else if ctx, err = s.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return ctx, err
	}

	return ctx, nil
}
func (s *Store) PersistRefreshTokenGrantSession(ctx context.Context, originalRefreshSignature, accessSignature, refreshSignature string, request fosite.Requester) (context.Context, error) {
	if ctx, err := s.DeleteRefreshTokenSession(ctx, originalRefreshSignature); err != nil {
		return ctx, err
	} else if ctx, err := s.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return ctx, err
	} else if ctx, err := s.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return ctx, err
	}

	return ctx, nil
}
