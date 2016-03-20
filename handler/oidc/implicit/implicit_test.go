package implicit

import (
	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/enigma/hmac"
	"github.com/ory-am/fosite/enigma/jwt"
	"github.com/ory-am/fosite/fosite-example/store"
	"github.com/ory-am/fosite/handler/core/implicit"
	oauthStrat "github.com/ory-am/fosite/handler/core/strategy"
	"github.com/ory-am/fosite/handler/oidc"
	"github.com/ory-am/fosite/handler/oidc/strategy"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
	"time"
)

var idStrategy = &strategy.JWTStrategy{
	Enigma: &jwt.Enigma{
		PrivateKey: []byte(jwt.TestCertificates[0][1]),
		PublicKey:  []byte(jwt.TestCertificates[1][1]),
	},
}

var hmacStrategy = &oauthStrat.HMACSHAStrategy{
	Enigma: &hmac.Enigma{
		GlobalSecret: []byte("some-super-cool-secret-that-nobody-knows"),
	},
}

func TestHandleAuthorizeEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	aresp := internal.NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()

	areq := fosite.NewAuthorizeRequest()
	httpreq := &http.Request{Form: url.Values{}}

	h := OpenIDConnectImplicitHandler{
		AuthorizeImplicitGrantTypeHandler: implicit.AuthorizeImplicitGrantTypeHandler{
			AccessTokenLifespan: time.Hour,
			AccessTokenStrategy: hmacStrategy,
			AccessTokenStorage:  store.NewStore(),
		},
		IDTokenHandleHelper: oidc.IDTokenHandleHelper{
			IDTokenStrategy: idStrategy,
		},
	}
	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should not do anything because request requirements are not met",
			setup:       func() {},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"id_token"}
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"token", "id_token"}
			},
		},
		{
			description: "should not do anything because request requirements are not met",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{}
				areq.Scopes = fosite.Arguments{"openid"}
			},
		},
		{
			description: "should pass",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"id_token"}
				areq.Scopes = fosite.Arguments{"openid"}
				aresp.EXPECT().AddFragment("id_token", gomock.Any())
				aresp.EXPECT().AddFragment(gomock.Any(), gomock.Any()).AnyTimes()
			},
		},
		{
			description: "should pass",
			setup: func() {
				areq.ResponseTypes = fosite.Arguments{"token", "id_token"}
				areq.Scopes = fosite.Arguments{"openid"}
				aresp.EXPECT().AddFragment("id_token", gomock.Any())
				aresp.EXPECT().AddFragment("access_token", gomock.Any())
				aresp.EXPECT().AddFragment(gomock.Any(), gomock.Any()).AnyTimes()
			},
		},
	} {
		err := h.HandleAuthorizeEndpointRequest(nil, httpreq, areq, aresp)
		assert.True(t, errors.Is(c.expectErr, err), "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}
