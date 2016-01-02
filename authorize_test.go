package fosite

import (
	"github.com/golang/mock/gomock"
	. "github.com/ory-am/fosite/client"
	. "github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
	"net/http"
	"net/url"
	"testing"
)

// TODO rfc6749 3.1. Authorization Endpoint
// The endpoint URI MAY include an "application/x-www-form-urlencoded" formatted (per Appendix B) query component
//
// rfc6749 3.1.2. Redirection Endpoint
// "The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3"
func TestGetRedirectURI(t *testing.T) {
	cf := &Config{}
	for _, c := range []struct {
		in       string
		isError  bool
		expected string
	}{
		{in: "", isError: true},
	} {
		values := url.Values{}
		values.Set("redirect_uri", c.in)
		res, err := cf.redirectFromValues(values)
		assert.Equal(t, c.isError, err != nil, "%s", err)
		if err == nil {
			assert.Equal(t, c.expected, res)
		}
	}
}

// rfc6749 10.6.
// Authorization Code Redirection URI Manipulation
// The authorization server	MUST require public clients and SHOULD require confidential clients
// to register their redirection URIs.  If a redirection URI is provided
// in the request, the authorization server MUST validate it against the
// registered value.
//
// rfc6819 4.4.1.7.
// Threat: Authorization "code" Leakage through Counterfeit Client
// The authorization server may also enforce the usage and validation
// of pre-registered redirect URIs (see Section 5.2.3.5).
func TestDoesClientWhiteListRedirect(t *testing.T) {
	var err error
	var redir string

	cf := &Config{}
	for k, c := range []struct {
		client   Client
		url      string
		isError  bool
		expected string
	}{
		{
			client:  &SecureClient{RedirectURIs: []string{""}},
			url:     "http://foo.com/cb",
			isError: true,
		},
		{
			client:  &SecureClient{RedirectURIs: []string{"http://bar.com/cb"}},
			url:     "http://foo.com/cb",
			isError: true,
		},
		{
			client:   &SecureClient{RedirectURIs: []string{"http://bar.com/cb"}},
			url:      "",
			isError:  false,
			expected: "http://bar.com/cb",
		},
		{
			client:  &SecureClient{RedirectURIs: []string{""}},
			url:     "",
			isError: true,
		},
		{
			client:   &SecureClient{RedirectURIs: []string{"http://bar.com/cb"}},
			url:      "http://bar.com/cb",
			isError:  false,
			expected: "http://bar.com/cb",
		},
		{
			client:  &SecureClient{RedirectURIs: []string{"http://bar.com/cb"}},
			url:     "http://bar.com/cb123",
			isError: true,
		},
	} {
		redir, err = cf.redirectFromClient(c.url, c.client)
		assert.Equal(t, c.isError, err != nil, "%d: %s", k, err)
		assert.Equal(t, c.expected, redir)
	}
}

func TestNewAuthorizeRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := NewMockStorage(ctrl)
	defer ctrl.Finish()

	for k, c := range []struct {
		conf    *Config
		r       *http.Request
		isError bool
		mock    func()
	}{
		{
			conf: &Config{},
			r: &http.Request{
				Header:   http.Header{"": []string{""}},
				Form:     url.Values{},
				PostForm: url.Values{},
			},
			mock: func() {
				//store.EXPECT().GetClient()
			},
			isError: true,
		},
	} {
		c.mock()
		_, err := c.conf.NewAuthorizeRequest(context.Background(), c.r, store)
		assert.Equal(t, c.isError, err != nil, "%d: %s", k, err)
	}
}
