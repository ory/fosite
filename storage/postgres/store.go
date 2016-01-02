package postgres

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/jmoiron/sqlx"
	"github.com/ory-am/fosite/client"
)

const (
	clientTable = "fosite_client"
)

type PGStore struct {
	DB *sqlx.DB
}

var schemata = []string{
	fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
	id       	  	 text NOT NULL PRIMARY KEY,
	secret		  	 text NOT NULL,
	redirect_uris 	 text NOT NULL,
	allow_user_grant bool false
)
`, clientTable),
}

func (s *PGStore) CreateSchemas() error {
	for _, schema := range schemata {
		if _, err := s.DB.Exec(schema); err != nil {
			return errors.Wrap(err, 1)
		}
	}
	return nil
}

func (s *PGStore) CreateClient(client.Client) error {
	return nil
}

func (s *PGStore) GetClient(id string) (client.Client, error) {
	return &client.SecureClient{}, nil
}
