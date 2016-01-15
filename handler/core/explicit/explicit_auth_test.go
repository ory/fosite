package explicit

import (
	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
)

func TestHandleAuthorizeEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockAuthorizeCodeGrantStorage(ctrl)
	chgen := internal.NewMockAuthorizeCodeStrategy(ctrl)
	areq := internal.NewMockAuthorizeRequester(ctrl)
	aresp := internal.NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()

	h := AuthorizeExplicitGrantTypeHandler{
		Store: store,
		AuthorizeCodeStrategy: chgen,
	}
	for k, c := range []struct {
		mock      func()
		req       *http.Request
		expectErr error
	}{
		{
			mock: func() {
				areq.EXPECT().GetResponseTypes().Return(fosite.Arguments{})
			},
		},
		{
			mock: func() {
				areq.EXPECT().GetResponseTypes().Return(fosite.Arguments{"foo"})
			},
		},
		{
			mock: func() {
				areq.EXPECT().GetResponseTypes().Return(fosite.Arguments{"code"})
				chgen.EXPECT().GenerateAuthorizeCode(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "", fosite.ErrServerError)
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{Form: url.Values{"redirect_uri": {"foobar"}}},
			mock: func() {
				areq.EXPECT().GetResponseTypes().Return(fosite.Arguments{"code"})
				chgen.EXPECT().GenerateAuthorizeCode(gomock.Any(), gomock.Any(), gomock.Any()).Return("", "", nil)
				store.EXPECT().CreateAuthorizeCodeSession(gomock.Any(), gomock.Any()).Return(fosite.ErrTemporarilyUnavailable)
			},
			expectErr: fosite.ErrServerError,
		},
		{
			req: &http.Request{Form: url.Values{"redirect_uri": {"foobar"}}},
			mock: func() {
				areq.EXPECT().GetResponseTypes().Return(fosite.Arguments{"code"})
				chgen.EXPECT().GenerateAuthorizeCode(gomock.Any(), gomock.Any(), gomock.Any()).Return("foo.bar", "bar", nil)
				store.EXPECT().CreateAuthorizeCodeSession("bar", gomock.Any()).Return(nil)

				aresp.EXPECT().AddQuery("code", "foo.bar")
				aresp.EXPECT().AddQuery("scope", gomock.Any())
				aresp.EXPECT().AddQuery("state", gomock.Any())
				areq.EXPECT().SetResponseTypeHandled("code")
				areq.EXPECT().GetGrantedScopes()
				areq.EXPECT().GetState()
			},
		},
	} {
		c.mock()
		err := h.HandleAuthorizeEndpointRequest(nil, c.req, areq, aresp)
		assert.True(t, errors.Is(c.expectErr, err), "%d\n%s\n%s", k, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
