package fosite_test

import (
	"github.com/golang/mock/gomock"
	. "github.com/ory-am/fosite"
	. "github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"github.com/vektra/errors"
	"golang.org/x/net/context"
	"net/http"
	"net/url"
	"testing"
)

func TestNewAuthorizeResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	handlers := []*MockAuthorizeEndpointHandler{NewMockAuthorizeEndpointHandler(ctrl)}
	ar := NewMockAuthorizeRequester(ctrl)
	defer ctrl.Finish()

	ctx := context.Background()
	oauth2 := &Fosite{
		AuthorizeEndpointHandlers: []AuthorizeEndpointHandler{handlers[0]},
	}
	duo := &Fosite{
		AuthorizeEndpointHandlers: []AuthorizeEndpointHandler{handlers[0], handlers[0]},
	}
	fooErr := errors.New("foo")
	for k, c := range []struct {
		isErr     bool
		mock      func()
		expectErr error
	}{
		{
			mock: func() {
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(fooErr)
			},
			isErr:     true,
			expectErr: fooErr,
		},
		{
			mock: func() {
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
			},
			isErr: false,
		},
		{
			mock: func() {
				oauth2 = duo
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				ar.EXPECT().DidHandleAllResponseTypes().Return(true)
			},
			isErr: false,
		},
		{
			mock: func() {
				oauth2 = duo
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().HandleAuthorizeEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(fooErr)
			},
			isErr:     true,
			expectErr: fooErr,
		},
	} {
		c.mock()
		responder, err := oauth2.NewAuthorizeResponse(ctx, &http.Request{}, ar, &struct{}{})
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

func TestWriteAuthorizeResponse(t *testing.T) {
	oauth2 := &Fosite{}
	header := http.Header{}
	ctrl := gomock.NewController(t)
	rw := NewMockResponseWriter(ctrl)
	ar := NewMockAuthorizeRequester(ctrl)
	resp := NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()

	for k, c := range []struct {
		setup  func()
		expect func()
	}{
		{
			setup: func() {
				redir, _ := url.Parse("http://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				resp.EXPECT().GetFragment().Return(url.Values{})
				resp.EXPECT().GetHeader().Return(http.Header{})
				resp.EXPECT().GetQuery().Return(url.Values{})

				rw.EXPECT().Header().Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					"Location": []string{"http://foobar.com/?foo=bar"},
				}, header)
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("http://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				resp.EXPECT().GetFragment().Return(url.Values{"bar": {"baz"}})
				resp.EXPECT().GetHeader().Return(http.Header{})
				resp.EXPECT().GetQuery().Return(url.Values{})

				rw.EXPECT().Header().Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					"Location": []string{"http://foobar.com/?foo=bar#bar=baz"},
				}, header)
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("http://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				resp.EXPECT().GetFragment().Return(url.Values{"bar": {"baz"}})
				resp.EXPECT().GetHeader().Return(http.Header{})
				resp.EXPECT().GetQuery().Return(url.Values{"bar": {"baz"}})

				rw.EXPECT().Header().Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					"Location": []string{"http://foobar.com/?bar=baz&foo=bar#bar=baz"},
				}, header)
			},
		},
		{
			setup: func() {
				redir, _ := url.Parse("http://foobar.com/?foo=bar")
				ar.EXPECT().GetRedirectURI().Return(redir)
				resp.EXPECT().GetFragment().Return(url.Values{"bar": {"baz"}})
				resp.EXPECT().GetHeader().Return(http.Header{"X-Bar": {"baz"}})
				resp.EXPECT().GetQuery().Return(url.Values{"bar": {"baz"}})

				rw.EXPECT().Header().Return(header)
				rw.EXPECT().WriteHeader(http.StatusFound)
			},
			expect: func() {
				assert.Equal(t, http.Header{
					"X-Bar":    {"baz"},
					"Location": {"http://foobar.com/?bar=baz&foo=bar#bar=baz"},
				}, header)
			},
		},
	} {
		t.Logf("Starting test case %d", k)
		c.setup()
		oauth2.WriteAuthorizeResponse(rw, ar, resp)
		c.expect()
		header = http.Header{}
		t.Logf("Passed test case %d", k)
	}
}
