package fosite_test

import (
	"net/url"
	"testing"
	"time"

	. "github.com/ory-am/fosite"
	"github.com/stretchr/testify/assert"
)

func TestRequest(t *testing.T) {
	r := &Request{
		RequestedAt:   time.Now(),
		Client:        &DefaultClient{},
		Scopes:        Arguments{},
		GrantedScopes: []string{},
		Form:          url.Values{"foo": []string{"bar"}},
		Session:       1234,
	}

	assert.Equal(t, r.RequestedAt, r.GetRequestedAt())
	assert.Equal(t, r.Client, r.GetClient())

}
