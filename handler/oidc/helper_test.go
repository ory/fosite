package oidc

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/go-errors/errors"
	"github.com/golang/mock/gomock"
	"github.com/ory-am/fosite"
	"github.com/ory-am/fosite/enigma/jwt"
	"github.com/ory-am/fosite/handler/oidc/strategy"
	"github.com/ory-am/fosite/internal"
	"github.com/stretchr/testify/assert"
)

var strat = &strategy.JWTStrategy{
	Enigma: &jwt.Enigma{
		PrivateKey: []byte(jwt.TestCertificates[0][1]),
		PublicKey:  []byte(jwt.TestCertificates[1][1]),
	},
}

func TestGenerateIDToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	chgen := internal.NewMockOpenIDConnectTokenStrategy(ctrl)
	defer ctrl.Finish()

	httpreq := &http.Request{Form: url.Values{}}
	ar := fosite.NewAccessRequest(nil)
	sess := &strategy.IDTokenSession{
		IDTokenClaims: &strategy.IDTokenClaims{},
		Header:        &jwt.Header{},
	}
	h := &IDTokenHandleHelper{IDTokenStrategy: chgen}

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should fail because nonce not set",
			setup:       func() {},
			expectErr:   fosite.ErrInsufficientEntropy,
		},
		{
			description: "should fail because nonce too short",
			setup: func() {
				ar.Form.Set("nonce", "1")
			},
			expectErr: fosite.ErrInsufficientEntropy,
		},
		{
			description: "should fail because session not set",
			setup: func() {
				ar.Form.Set("nonce", "11111111111111111111111111111111111")
			},
			expectErr: fosite.ErrMisconfiguration,
		},
		{
			description: "should fail because generator failed",
			setup: func() {
				ar.SetSession(sess)
				chgen.EXPECT().GenerateIDToken(nil, httpreq, ar).Return("", errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "should pass",
			setup: func() {
				chgen.EXPECT().GenerateIDToken(nil, httpreq, ar).AnyTimes().Return("asdf", nil)
			},
		},
	} {
		c.setup()
		token, err := h.generateIDToken(nil, httpreq, ar)
		assert.True(t, errors.Is(c.expectErr, err), "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		if err == nil {
			assert.NotEmpty(t, token, "(%d) %s", k, c.description)
		}
		t.Logf("Passed test case %d", k)
	}

}

func TestIssueExplicitToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	resp := internal.NewMockAccessResponder(ctrl)
	defer ctrl.Finish()

	httpreq := &http.Request{}
	ar := fosite.NewAuthorizeRequest()
	ar.Form = url.Values{"nonce": {"111111111111"}}
	ar.SetSession(&strategy.IDTokenSession{IDTokenClaims: &strategy.IDTokenClaims{}, Header: &jwt.Header{}})

	resp.EXPECT().SetExtra("id_token", gomock.Any())
	h := &IDTokenHandleHelper{IDTokenStrategy: strat}
	err := h.IssueExplicitIDToken(nil, httpreq, ar, resp)
	assert.Nil(t, err, "%s", err)
}

func TestIssueImplicitToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	resp := internal.NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()

	httpreq := &http.Request{}
	ar := fosite.NewAuthorizeRequest()
	ar.Form = url.Values{"nonce": {"111111111111"}}
	ar.SetSession(&strategy.IDTokenSession{IDTokenClaims: &strategy.IDTokenClaims{}, Header: &jwt.Header{}})

	resp.EXPECT().AddFragment("id_token", gomock.Any())
	h := &IDTokenHandleHelper{IDTokenStrategy: strat}
	err := h.IssueImplicitIDToken(nil, httpreq, ar, resp)
	assert.Nil(t, err, "%s", err)
}
