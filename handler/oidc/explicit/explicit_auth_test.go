package explicit

import (
	"github.com/golang/mock/gomock"
	"github.com/ory-am/fosite/internal"
	"testing"
	"net/url"
	"net/http"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/enigma/jwt"
	"github.com/ory-am/fosite/handler/oidc/strategy"
	"github.com/stretchr/testify/assert"
	"github.com/go-errors/errors"
	"github.com/ory-am/fosite/handler/oidc"
)

var j = &strategy.JWTStrategy{
	Enigma: &jwt.Enigma{
		PrivateKey: []byte(jwt.TestCertificates[0][1]),
		PublicKey:  []byte(jwt.TestCertificates[1][1]),
	},
}

func TestHandleAuthorizeEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockOpenIDConnectRequestStorage(ctrl)
	aresp := internal.NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()


	areq := fosite.NewAuthorizeRequest()
	httpreq := &http.Request{Form: url.Values{}}

	h := &OpenIDConnectExplicitHandler{
		OpenIDConnectRequestStorage: store,
		IDTokenHandleHelper: &oidc.IDTokenHandleHelper{
			IDTokenStrategy: j,
		},
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
			description: "should pass because scope openid is not set",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"code"}
				areq.Scopes = fosite.Arguments{""}
			},
		},
		{
			description: "should fail because session is not set",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"code"}
				areq.Scopes = fosite.Arguments{"openid"}
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should fail because no nonce set",
			setup: func() {
				areq.Session = &strategy.IDTokenSession{
					IDClaims: &jwt.Claims{},
					IDToken: &jwt.Header{},
				}
			},
			expectErr: fosite.ErrInsufficientEntropy,
		},
		{
			description: "should fail because nonce to short",
			setup: func() {
				areq.Form.Set("nonce", "1")
			},
			expectErr: fosite.ErrInsufficientEntropy,
		},
		{
			description: "should fail because no code set",
			setup: func() {
				areq.Form.Set("nonce", "11111111111111111111111111111")
				aresp.EXPECT().GetCode().Return("")
			},
			expectErr: fosite.ErrMisconfiguration,
		},
		{
			description: "should fail because lookup fails",
			setup: func() {
				aresp.EXPECT().GetCode().AnyTimes().Return("codeexample")
				store.EXPECT().CreateOpenIDConnectSession(nil, "codeexample", areq).Return(errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should pass",
			setup: func() {
				store.EXPECT().CreateOpenIDConnectSession(nil, "codeexample", areq).AnyTimes().Return(nil)
			},
		},
	} {
		c.setup()
		err := h.HandleAuthorizeEndpointRequest(nil, httpreq, areq, aresp)
		assert.True(t, errors.Is(c.expectErr, err), "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}