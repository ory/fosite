package fosite_test

import (
	"github.com/golang/mock/gomock"
	"github.com/ory-am/common/pkg"
	. "github.com/ory-am/fosite"
	. "github.com/ory-am/fosite/client"
	. "github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"github.com/vektra/errors"
	"golang.org/x/net/context"
	"net/http"
	"net/url"
	"testing"
)

func TestNewNewAuthorizeResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	handlers := []*MockResponseTypeHandler{NewMockResponseTypeHandler(ctrl)}
	defer ctrl.Finish()

	ctx := context.Background()
	oauth2 := &Fosite{
		ResponseTypeHandlers: []ResponseTypeHandler{handlers[0]},
	}
	duo := &Fosite{
		ResponseTypeHandlers: []ResponseTypeHandler{handlers[0], handlers[0]},
	}
	fooErr := errors.New("foo")
	for k, c := range []struct {
		isErr     bool
		mock      func()
		expectErr error
	}{
		{
			mock: func() {
				handlers[0].EXPECT().HandleResponseType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(fooErr)
			},
			isErr:     true,
			expectErr: fooErr,
		},
		{
			mock: func() {
				handlers[0].EXPECT().HandleResponseType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrInvalidResponseType)
			},
			isErr:     true,
			expectErr: ErrNoResponseTypeHandlerFound,
		},
		{
			mock: func() {
				handlers[0].EXPECT().HandleResponseType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			isErr: false,
		},
		{
			mock: func() {
				oauth2 = duo
				handlers[0].EXPECT().HandleResponseType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().HandleResponseType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			isErr: false,
		},
		{
			mock: func() {
				oauth2 = duo
				handlers[0].EXPECT().HandleResponseType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().HandleResponseType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrInvalidResponseType)
			},
			isErr: false,
		},
		{
			mock: func() {
				oauth2 = duo
				handlers[0].EXPECT().HandleResponseType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().HandleResponseType(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(fooErr)
			},
			isErr:     true,
			expectErr: fooErr,
		},
	} {
		c.mock()
		responder, err := oauth2.NewAuthorizeResponse(ctx, nil, nil, nil)
		assert.Equal(t, c.isErr, err != nil, "%d: %s", k, err)
		if err != nil {
			assert.Equal(t, c.expectErr, err, "%d: %s", k, err)
			assert.Nil(t, responder, "%d", k)
		} else {
			assert.NotNil(t, responder, "%d", k)
		}
		t.Logf("Passed test case %d", k)
	}
}

// Test for
// * https://tools.ietf.org/html/rfc6749#section-4.1.2.1
//   If the request fails due to a missing, invalid, or mismatching
//   redirection URI, or if the client identifier is missing or invalid,
//   the authorization server SHOULD inform the resource owner of the
//   error and MUST NOT automatically redirect the user-agent to the
//   invalid redirection URI.
// * https://tools.ietf.org/html/rfc6749#section-3.1.2
//   The redirection endpoint URI MUST be an absolute URI as defined by
//   [RFC3986] Section 4.3.  The endpoint URI MAY include an
//   "application/x-www-form-urlencoded" formatted (per Appendix B) query
//   component ([RFC3986] Section 3.4), which MUST be retained when adding
//   additional query parameters.  The endpoint URI MUST NOT include a
//   fragment component.
func TestWriteAuthorizeError(t *testing.T) {
	ctrl := gomock.NewController(t)
	rw := NewMockResponseWriter(ctrl)
	req := NewMockAuthorizeRequester(ctrl)
	defer ctrl.Finish()

	var urls = []string{
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
		err         error
		mock        func()
		checkHeader func(int)
	}{
		{
			err: ErrInvalidGrant,
			mock: func() {
				req.EXPECT().IsRedirectURIValid().Return(false)
				rw.EXPECT().Header().Return(header)
				rw.EXPECT().WriteHeader(http.StatusOK)
				rw.EXPECT().Write(gomock.Any())
			},
			checkHeader: func(k int) {
				assert.Equal(t, "application/json", header.Get("Content-Type"), "%d", k)
			},
		},
		{
			err: ErrInvalidRequest,
			mock: func() {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(purls[0])
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
			err: ErrInvalidRequest,
			mock: func() {
				req.EXPECT().IsRedirectURIValid().Return(true)
				req.EXPECT().GetRedirectURI().Return(purls[1])
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
		oauth2.WriteAuthorizeError(rw, req, c.err)
		c.checkHeader(k)
		header = http.Header{}
		t.Logf("Passed test case %d", k)
	}
}

// Should pass
//
// * https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Terminology
//   The OAuth 2.0 specification allows for registration of space-separated response_type parameter values.
//   If a Response Type contains one of more space characters (%20), it is compared as a space-delimited list of
//   values in which the order of values does not matter.
func TestNewAuthorizeRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := NewMockStorage(ctrl)
	defer ctrl.Finish()

	redir, _ := url.Parse("http://foo.bar/cb")
	for k, c := range []struct {
		desc          string
		conf          *Fosite
		r             *http.Request
		query         url.Values
		expectedError error
		mock          func()
		expect        *AuthorizeRequest
	}{
		/* empty request */
		{
			desc:          "empty request fails",
			conf:          &Fosite{Store: store},
			r:             &http.Request{},
			expectedError: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		/* invalid redirect uri */
		{
			desc:          "invalid redirect uri fails",
			conf:          &Fosite{Store: store},
			query:         url.Values{"redirect_uri": []string{"invalid"}},
			expectedError: ErrInvalidClient,
			mock: func() {
				store.EXPECT().GetClient(gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		/* invalid client */
		{
			desc:          "invalid client fails",
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
				"client_id": []string{"1234"},
			},
			expectedError: ErrInvalidRequest,
			mock: func() {
				store.EXPECT().GetClient("1234").Return(&SecureClient{RedirectURIs: []string{"invalid"}}, nil)
			},
		},
		/* redirect client mismatch */
		{
			desc: "client and request redirects mismatch",
			conf: &Fosite{Store: store},
			query: url.Values{
				"redirect_uri": []string{""},
				"client_id":    []string{"1234"},
			},
			expectedError: ErrInvalidRequest,
			mock: func() {
				store.EXPECT().GetClient("1234").Return(&SecureClient{RedirectURIs: []string{"invalid"}}, nil)
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
		/* no state */
		{
			desc: "no state",
			conf: &Fosite{Store: store},
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
			conf: &Fosite{Store: store},
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
		/* success case */
		{
			desc: "should pass",
			conf: &Fosite{Store: store},
			query: url.Values{
				"redirect_uri":  []string{"http://foo.bar/cb"},
				"client_id":     []string{"1234"},
				"response_type": []string{"code token"},
				"state":         []string{"strong-state"},
				"scope":         []string{"foo bar"},
			},
			mock: func() {
				store.EXPECT().GetClient("1234").Return(&SecureClient{RedirectURIs: []string{"http://foo.bar/cb"}}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				Client:        &SecureClient{RedirectURIs: []string{"http://foo.bar/cb"}},
				ResponseTypes: []string{"code", "token"},
				State:         "strong-state",
				Scopes:        []string{"foo", "bar"},
			},
		},
	} {
		t.Logf("Joining test case %d", k)
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
		} else {
			pkg.AssertObjectKeysEqual(t, c.expect, ar, "ResponseTypes", "Scopes", "Client", "RedirectURI", "State")
			assert.NotNil(t, ar.GetRequestedAt())
		}
		t.Logf("Passed test case %d", k)
	}
}
