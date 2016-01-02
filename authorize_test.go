package fosite

import (
	"github.com/golang/mock/gomock"
	. "github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/generator"
	. "github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"github.com/vektra/errors"
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
	for _, c := range []struct {
		in       string
		isError  bool
		expected string
	}{
		{in: "", isError: true},
	} {
		values := url.Values{}
		values.Set("redirect_uri", c.in)
		res, err := redirectFromValues(values)
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
		redir, err = redirectFromClient(c.url, c.client)
		assert.Equal(t, c.isError, err != nil, "%d: %s", k, err)
		assert.Equal(t, c.expected, redir)
	}
}

func TestNewAuthorizeRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := NewMockStorage(ctrl)
	gen := NewMockGenerator(ctrl)
	defer ctrl.Finish()

	for k, c := range []struct {
		desc          string
		conf          *Config
		r             *http.Request
		query         url.Values
		expectedError error
		mock          func()
		expect        *AuthorizeRequest
	}{
		/* empty request */
		{
			desc:          "empty request fails",
			conf:          &Config{Store: store},
			r:             &http.Request{},
			expectedError: ErrInvalidRequest,
			mock:          func() {},
		},
		/* invalid redirect uri */
		{
			desc:          "invalid redirect uri fails",
			conf:          &Config{Store: store},
			query:         url.Values{"redirect_uri": []string{"invalid"}},
			expectedError: ErrInvalidRequest,
			mock:          func() {},
		},
		/* invalid client */
		{
			desc:          "invalid client uri fails",
			conf:          &Config{Store: store},
			query:         url.Values{"redirect_uri": []string{"http://foo.bar/cb"}},
			expectedError: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		/* redirect client mismatch */
		{
			desc: "client and request redirects mismatch",
			conf: &Config{Store: store},
			query: url.Values{
				"redirect_uri": []string{"http://foo.bar/cb"},
				"client_id":    []string{"1234"},
			},
			expectedError: ErrInvalidRequest,
			mock: func() {
				store.EXPECT().GetClient("1234").Return(&SecureClient{RedirectURIs: []string{"invalid"}}, nil)
			},
		},
		/* no response type */
		{
			desc: "no response type",
			conf: &Config{Store: store},
			query: url.Values{
				"redirect_uri": []string{"http://foo.bar/cb"},
				"client_id":    []string{"1234"},
			},
			expectedError: ErrUnsupportedResponseType,
			mock: func() {
				store.EXPECT().GetClient("1234").Return(&SecureClient{RedirectURIs: []string{"http://foo.bar/cb"}}, nil)
			},
		},
		/* invalid response type */
		{
			desc: "invalid response type",
			conf: &Config{Store: store},
			query: url.Values{
				"redirect_uri":  []string{"http://foo.bar/cb"},
				"client_id":     []string{"1234"},
				"response_type": []string{"foo"},
			},
			expectedError: ErrUnsupportedResponseType,
			mock: func() {
				store.EXPECT().GetClient("1234").Return(&SecureClient{RedirectURIs: []string{"http://foo.bar/cb"}}, nil)
			},
		},
		/* invalid response type */
		{
			desc: "invalid response type",
			conf: &Config{Store: store},
			query: url.Values{
				"redirect_uri":  []string{"http://foo.bar/cb"},
				"client_id":     []string{"1234"},
				"response_type": []string{"foo"},
			},
			expectedError: ErrUnsupportedResponseType,
			mock: func() {
				store.EXPECT().GetClient("1234").Return(&SecureClient{RedirectURIs: []string{"http://foo.bar/cb"}}, nil)
			},
		},
		/* unsupported response type */
		{
			desc: "unspported response type",
			conf: &Config{Store: store, AllowedResponseTypes: []string{"code"}},
			query: url.Values{
				"redirect_uri":  []string{"http://foo.bar/cb"},
				"client_id":     []string{"1234"},
				"response_type": []string{"code token"},
			},
			expectedError: ErrUnsupportedResponseType,
			mock: func() {
				store.EXPECT().GetClient("1234").Return(&SecureClient{RedirectURIs: []string{"http://foo.bar/cb"}}, nil)
			},
		},
		/* unsupported response type */
		{
			desc: "unspported response type",
			conf: &Config{Store: store, AllowedResponseTypes: []string{"code"}},
			query: url.Values{
				"redirect_uri":  []string{"http://foo.bar/cb"},
				"client_id":     []string{"1234"},
				"response_type": []string{"foo"},
			},
			expectedError: ErrUnsupportedResponseType,
			mock: func() {
				store.EXPECT().GetClient("1234").Return(&SecureClient{RedirectURIs: []string{"http://foo.bar/cb"}}, nil)
			},
		},
		/* no state */
		{
			desc: "no state",
			conf: &Config{Store: store, AllowedResponseTypes: []string{"code"}},
			query: url.Values{
				"redirect_uri":  []string{"http://foo.bar/cb"},
				"client_id":     []string{"1234"},
				"response_type": []string{"code"},
			},
			expectedError: ErrInvalidState,
			mock: func() {
				store.EXPECT().GetClient("1234").Return(&SecureClient{RedirectURIs: []string{"http://foo.bar/cb"}}, nil)
			},
		},
		/* short state */
		{
			desc: "short state",
			conf: &Config{Store: store, AllowedResponseTypes: []string{"code"}},
			query: url.Values{
				"redirect_uri":  []string{"http://foo.bar/cb"},
				"client_id":     []string{"1234"},
				"response_type": []string{"code"},
				"state":         []string{"short"},
			},
			expectedError: ErrInvalidState,
			mock: func() {
				store.EXPECT().GetClient("1234").Return(&SecureClient{RedirectURIs: []string{"http://foo.bar/cb"}}, nil)
			},
		},
		/* code gen fails */
		{
			desc: "code gen fails",
			conf: &Config{Store: store, AuthorizeCodeGenerator: gen, AllowedResponseTypes: []string{"code"}},
			query: url.Values{
				"redirect_uri":  []string{"http://foo.bar/cb"},
				"client_id":     []string{"1234"},
				"response_type": []string{"code"},
				"state":         []string{"strong-state"},
			},
			expectedError: ErrServerError,
			mock: func() {
				gen.EXPECT().Generate().Return(nil, errors.New(""))
				store.EXPECT().GetClient("1234").Return(&SecureClient{RedirectURIs: []string{"http://foo.bar/cb"}}, nil)
			},
		},
		/* success case */
		{
			desc: "should pass",
			conf: &Config{
				Store: store,
				AuthorizeCodeGenerator: gen,
				AllowedResponseTypes:   []string{"code", "token"},
				Lifetime:               3600,
			},
			query: url.Values{
				"redirect_uri":  []string{"http://foo.bar/cb"},
				"client_id":     []string{"1234"},
				"response_type": []string{"code token"},
				"state":         []string{"strong-state"},
				"scope":         []string{"foo bar"},
			},
			mock: func() {
				gen.EXPECT().Generate().Return(&generator.Token{Key: "foo", Signature: "bar"}, nil)
				store.EXPECT().GetClient("1234").Return(&SecureClient{RedirectURIs: []string{"http://foo.bar/cb"}}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   "http://foo.bar/cb",
				Client:        &SecureClient{RedirectURIs: []string{"http://foo.bar/cb"}},
				ResponseTypes: []string{"code", "token"},
				State:         "strong-state",
				Scopes:        []string{"foo", "bar"},
				ExpiresIn:     3600,
				Code:          &generator.Token{Key: "foo", Signature: "bar"},
			},
		},
	} {
		c.mock()
		if c.r == nil {
			c.r = &http.Request{Header: http.Header{}}
			if c.query != nil {
				c.r.URL = &url.URL{RawQuery: c.query.Encode()}
			}
		}

		ar, err := c.conf.NewAuthorizeRequest(context.Background(), c.r)
		assert.Equal(t, c.expectedError == nil, err == nil, "%d: %s\n%s", k, c.desc, err)
		if c.expectedError != nil {
			assert.Equal(t, err.Error(), c.expectedError.Error(), "%d: %s\n%s", k, c.desc, err)
		}
		assert.Equal(t, c.expect, ar, "%d: %s\n", k, c.desc)
	}
}
