package fosite_test

import (
	"github.com/golang/mock/gomock"
	. "github.com/ory-am/fosite"
	. "github.com/ory-am/fosite/client"
	"github.com/ory-am/fosite/generator"
	. "github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	oauth2 := &OAuth2{Store: store}
	for k, c := range []struct {
		ar          AuthorizeRequest
		resp        AuthorizeResponse
		isErr       bool
		mock        func()
		checkHeader func(int)
	}{
		{
			ar: AuthorizeRequest{RedirectURI: redir},
			resp: AuthorizeResponse{
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
				//rw.EXPECT().Header().Return(header)
				//rw.EXPECT().WriteHeader(http.StatusFound)
			},
			checkHeader: func(k int) {
				//assert.Equal(t, "http://foobar.com/?baz=bar&foo=baz", header.Get("Location"), "%d", k)
				//assert.Equal(t, "bar", header.Get("foo"), "%d", k)
				//assert.Equal(t, "http://foobar.com/?baz=bar&foo=baz", header.Get("Location"), "%d", k)
			},
			isErr: true,
		},
		{
			ar: AuthorizeRequest{RedirectURI: redir},
			resp: AuthorizeResponse{
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

	oauth2 := &OAuth2{}
	header := http.Header{}
	for k, c := range []struct {
		ar          AuthorizeRequest
		err         error
		mock        func()
		checkHeader func(int)
	}{
		{
			ar:  AuthorizeRequest{RedirectURI: purls[0]},
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
			ar:  AuthorizeRequest{RedirectURI: purls[1]},
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
			ar:  AuthorizeRequest{RedirectURI: purls[2]},
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

func TestAuthorizeWorkflow(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := NewMockStorage(ctrl)
	gen := NewMockGenerator(ctrl)
	defer ctrl.Finish()

	redir, _ := url.Parse("http://foo.bar/cb")

	for k, c := range []struct {
		desc          string
		conf          *OAuth2
		r             *http.Request
		query         url.Values
		expectedError error
		mock          func()
		expect        *AuthorizeRequest
	}{
		{
			desc: "should pass",
			conf: &OAuth2{
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
				RedirectURI:   redir,
				Client:        &SecureClient{ID: "1234", RedirectURIs: []string{"http://foo.bar/cb"}},
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

		// equals to: c.conf = NewDefaultOAuth2(store)
		c.conf.Store = store
		authorizeRequest, err := c.conf.NewAuthorizeRequest(context.Background(), c.r)
		require.Nil(t, err, "%d: %s", k, err)

		userID := "user-id"
		_ = NewAuthorizeSessionSQL(authorizeRequest, userID)

		// 	if err := store.StoreAuthorizeSession(sess); err != nil {
		// 		return err
		// 	}

		//response := NewAuthorizeResponse()
		// err = oauth2.HandleResponseTypes(authorizeRequest, response, session)
		// err = alsoHandleMyCustomResponseType(authorizeRequest, response, "fancyArguments", 1234)
		//
		// or
		//
		// this approach would make it possible to check if all response types could be served or not
		// additionally, a callback for FinishAccessRequest could be provided
		//
		// response = &AuthorizeResponse{}
		// oauth2.RegisterResponseTypeHandler("custom_type", alsoHandleMyCustomResponseType)
		// err = oauth2.HandleResponseTypes(authorizeRequest, response, session)
		// ****

		// Almost done! The next step is going to persist the session in the database for later use.
		// It is additionally going to output a result based on response_type.

		// ** API not finalized yet **
		// err := oauth2.FinishAuthorizeRequest(rw, response, session)
		// ****
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
		conf          *OAuth2
		r             *http.Request
		query         url.Values
		expectedError error
		mock          func()
		expect        *AuthorizeRequest
	}{
		/* empty request */
		{
			desc:          "empty request fails",
			conf:          &OAuth2{Store: store},
			r:             &http.Request{},
			expectedError: ErrInvalidRequest,
			mock:          func() {},
		},
		/* invalid redirect uri */
		{
			desc:          "invalid redirect uri fails",
			conf:          &OAuth2{Store: store},
			query:         url.Values{"redirect_uri": []string{"invalid"}},
			expectedError: ErrInvalidRequest,
			mock:          func() {},
		},
		/* invalid client */
		{
			desc:          "invalid client uri fails",
			conf:          &OAuth2{Store: store},
			query:         url.Values{"redirect_uri": []string{"http://foo.bar/cb"}},
			expectedError: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		/* redirect client mismatch */
		{
			desc: "client and request redirects mismatch",
			conf: &OAuth2{Store: store},
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
			conf: &OAuth2{Store: store},
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
			conf: &OAuth2{Store: store},
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
			conf: &OAuth2{Store: store},
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
			conf: &OAuth2{Store: store, AllowedResponseTypes: []string{"code"}},
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
			conf: &OAuth2{Store: store, AllowedResponseTypes: []string{"code"}},
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
			conf: &OAuth2{Store: store, AllowedResponseTypes: []string{"code"}},
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
			conf: &OAuth2{Store: store, AllowedResponseTypes: []string{"code"}},
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
			conf: &OAuth2{Store: store, AuthorizeCodeGenerator: gen, AllowedResponseTypes: []string{"code"}},
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
			conf: &OAuth2{
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
