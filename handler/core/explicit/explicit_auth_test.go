package explicit

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
"strings"
)

func TestHandleAuthorizeEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockAuthorizeCodeGrantStorage(ctrl)
	chgen := internal.NewMockAuthorizeCodeStrategy(ctrl)
	aresp := internal.NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()

	areq := fosite.NewAuthorizeRequest()
	httpreq := &http.Request{Form: url.Values{}}

	h := AuthorizeExplicitGrantTypeHandler{
		Store: store,
		AuthorizeCodeStrategy: chgen,
	}
	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should pass because not responsible for handling an empty response type",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{""}
			},
		},
		{
			description: "should pass because not responsible for handling an invalid response type",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"foo"}
			},
		},
		{
			description: "should fail because authorize code generation failed",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"code"}
				chgen.EXPECT().GenerateAuthorizeCode(nil, httpreq, areq).Return("", "", errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should fail because could not presist authorize code session",
			setup: func() {
				chgen.EXPECT().GenerateAuthorizeCode(nil, httpreq, areq).AnyTimes().Return("someauthcode.authsig", "authsig", nil)
				store.EXPECT().CreateAuthorizeCodeSession(nil, "authsig", areq).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should pass",
			setup: func() {
				areq.GrantedScopes = fosite.Arguments{"a", "b"}
				areq.State = "superstate"
				store.EXPECT().CreateAuthorizeCodeSession(nil, "authsig", areq).Return(nil)
				aresp.EXPECT().AddQuery("code", "someauthcode.authsig")
				aresp.EXPECT().AddQuery("scope", strings.Join(areq.GrantedScopes, " "))
				aresp.EXPECT().AddQuery("state", areq.State)
			},
		},
	} {
		c.setup()
		err := h.HandleAuthorizeEndpointRequest(nil, httpreq, areq, aresp)
		assert.True(t, errors.Is(c.expectErr, err), "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
