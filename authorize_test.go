package fosite_test

import (
	"github.com/golang/mock/gomock"
	. "github.com/ory-am/fosite"
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

func TestFinishAuthorizeRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	rw := NewMockResponseWriter(ctrl)
	store := NewMockStorage(ctrl)
	defer ctrl.Finish()

	redir, _ := url.Parse("http://foobar.com/")
	header := http.Header{}
	oauth2 := &Fosite{Store: store}
	for k, c := range []struct {
		ar          AuthorizeRequester
		resp        AuthorizeResponder
		isErr       bool
		mock        func()
		checkHeader func(int)
	}{
		{
			ar: AuthorizeRequester{RedirectURI: redir},
			resp: AuthorizeResponder{
				Header: http.Header{
					"foo": []string{"bar"},
				},
				Query: url.Values{
					"baz": []string{"bar"},
					"foo": []string{"baz"},
				},
			},
			mock: func() {
				store.EXPECT().StoreAuthorizeSession(gomock.Nil()).Return(ErrServerError)
			},
			checkHeader: func(_ int) {},
			isErr:       true,
		},
		{
			ar: AuthorizeRequester{RedirectURI: redir},
			resp: AuthorizeResponder{
				Header: http.Header{
					"foo": []string{"x-bar"},
				},
				Query: url.Values{
					"baz": []string{"bar"},
					"foo": []string{"baz"},
				},
			},
			mock: func() {
				store.EXPECT().StoreAuthorizeSession(gomock.Nil()).Return(nil)
				rw.EXPECT().Header().AnyTimes().Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			checkHeader: func(k int) {
				assert.Equal(t, "x-bar", header.Get("Foo"), "%d: %s", k, header)
				assert.Equal(t, "http://foobar.com/?baz=bar&foo=baz", header.Get("Location"), "%d", k)
			},
			isErr: false,
		},
	} {
		c.mock()
		err := oauth2.FinishAuthorizeRequest(rw, c.ar, c.resp, nil)
		assert.Equal(t, c.isErr, err != nil, "%d: %s", k, err)
		if err == nil {
			c.checkHeader(k)
		}
		header = http.Header{}
	}
}

// https://tools.ietf.org/html/rfc6749#section-4.1.2.1
// If the request fails due to a missing, invalid, or mismatching
// redirection URI, or if the client identifier is missing or invalid,
// the authorization server SHOULD inform the resource owner of the
// error and MUST NOT automatically redirect the user-agent to the
// invalid redirection URI.
func TestWriteAuthorizeError(t *testing.T) {
	ctrl := gomock.NewController(t)
	rw := NewMockResponseWriter(ctrl)
	defer ctrl.Finish()

	var urls = []string{
		"",
		"http://foobar.com/",
		"http://foobar.com/?foo=bar",
	}
	var purls = []*url.URL{}
	for _, u := range urls {
		purl, _ := url.Parse(u)
		purls = append(purls, purl)
	}

	oauth2 := &Fosite{}
	header := http.Header{}
	for k, c := range []struct {
		ar          AuthorizeRequester
		err         error
		mock        func()
		checkHeader func(int)
	}{
		{
			ar:  AuthorizeRequester{RedirectURI: purls[0]},
			err: ErrInvalidGrant,
			mock: func() {
				rw.EXPECT().Header().Return(header)
				rw.EXPECT().WriteHeader(http.StatusOK)
				rw.EXPECT().Write(gomock.Any())
			},
			checkHeader: func(k int) {
				assert.Equal(t, "application/json", header.Get("Content-Type"), "%d", k)
			},
		},
		{
			ar:  AuthorizeRequester{RedirectURI: purls[1]},
			err: ErrInvalidRequest,
			mock: func() {
				rw.EXPECT().Header().Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			checkHeader: func(k int) {
				a, _ := url.Parse("http://foobar.com/?error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed")
				b, _ := url.Parse(header.Get("Location"))
				assert.Equal(t, a, b, "%d", k)
			},
		},
		{
			ar:  AuthorizeRequester{RedirectURI: purls[2]},
			err: ErrInvalidRequest,
			mock: func() {
				rw.EXPECT().Header().Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			checkHeader: func(k int) {
				a, _ := url.Parse("http://foobar.com/?error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+invalid+parameter+value%2C+includes+a+parameter+more+than+once%2C+or+is+otherwise+malformed&foo=bar")
				b, _ := url.Parse(header.Get("Location"))
				assert.Equal(t, a, b, "%d", k)
			},
		},
	} {
		c.mock()
		ar := c.ar
		oauth2.WriteAuthorizeError(rw, ar, c.err)
		assert.Equal(t, c.ar, ar, "%d", k)
		c.checkHeader(k)
		header = http.Header{}
	}
}

func TestNewAuthorizeRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := NewMockStorage(ctrl)
	gen := NewMockGenerator(ctrl)
	defer ctrl.Finish()

	redir, _ := url.Parse("http://foo.bar/cb")
	for k, c := range []struct {
		desc          string
		conf          *Fosite
		r             *http.Request
		query         url.Values
		expectedError error
		mock          func()
		expect        *AuthorizeRequester
	}{
		/* empty request */
		{
			desc:          "empty request fails",
			conf:          &Fosite{Store: store},
			r:             &http.Request{},
			expectedError: ErrInvalidRequest,
			mock:          func() {},
		},
		/* invalid redirect uri */
		{
			desc:          "invalid redirect uri fails",
			conf:          &Fosite{Store: store},
			query:         url.Values{"redirect_uri": []string{"invalid"}},
			expectedError: ErrInvalidRequest,
			mock:          func() {},
		},
		/* invalid client */
		{
			desc:          "invalid client uri fails",
			conf:          &Fosite{Store: store},
			query:         url.Values{"redirect_uri": []string{"http://foo.bar/cb"}},
			expectedError: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		/* redirect client mismatch */
		{
			desc: "client and request redirects mismatch",
			conf: &Fosite{Store: store},
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
			conf: &Fosite{Store: store},
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
			conf: &Fosite{Store: store},
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
			conf: &Fosite{Store: store},
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
			conf: &Fosite{Store: store, AllowedResponseTypes: []string{"code"}},
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
			conf: &Fosite{Store: store, AllowedResponseTypes: []string{"code"}},
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
			conf: &Fosite{Store: store, AllowedResponseTypes: []string{"code"}},
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
			conf: &Fosite{Store: store, AllowedResponseTypes: []string{"code"}},
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
			conf: &Fosite{Store: store, AuthorizeCodeGenerator: gen, AllowedResponseTypes: []string{"code"}},
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
			conf: &Fosite{
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
			expect: &AuthorizeRequester{
				RedirectURI:   redir,
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
