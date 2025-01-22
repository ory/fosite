// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/ory/fosite/internal/gen"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	gomock "go.uber.org/mock/gomock"

	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/token/jwt"
)

var strat = &DefaultStrategy{
	Signer: &jwt.DefaultSigner{
		GetPrivateKey: func(_ context.Context) (interface{}, error) {
			return gen.MustRSAKey(), nil
		},
	},
	Config: &fosite.Config{
		MinParameterEntropy: fosite.MinParameterEntropy,
	},
}

var fooErr = errors.New("foo")

func TestGenerateIDToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	chgen := internal.NewMockOpenIDConnectTokenStrategy(ctrl)
	defer ctrl.Finish()

	ar := fosite.NewAccessRequest(nil)
	sess := &DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject: "peter",
		},
		Headers: &jwt.Headers{},
	}
	h := &IDTokenHandleHelper{IDTokenStrategy: chgen}

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should fail because generator failed",
			setup: func() {
				ar.Form.Set("nonce", "11111111111111111111111111111111111")
				ar.SetSession(sess)
				chgen.EXPECT().GenerateIDToken(gomock.Any(), time.Duration(0), ar).Return("", fooErr)
			},
			expectErr: fooErr,
		},
		{
			description: "should pass",
			setup: func() {
				chgen.EXPECT().GenerateIDToken(gomock.Any(), time.Duration(0), ar).AnyTimes().Return("asdf", nil)
			},
		},
	} {
		c.setup()
		token, err := h.generateIDToken(context.Background(), time.Duration(0), ar)
		assert.True(t, err == c.expectErr, "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
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

	ar := fosite.NewAuthorizeRequest()
	ar.Form = url.Values{"nonce": {"111111111111"}}
	ar.SetSession(&DefaultSession{Claims: &jwt.IDTokenClaims{
		Subject: "peter",
	}, Headers: &jwt.Headers{}})

	resp.EXPECT().SetExtra("id_token", gomock.Any())
	h := &IDTokenHandleHelper{IDTokenStrategy: strat}
	err := h.IssueExplicitIDToken(context.Background(), time.Duration(0), ar, resp)
	assert.NoError(t, err)
}

func TestIssueImplicitToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	resp := internal.NewMockAuthorizeResponder(ctrl)
	defer ctrl.Finish()

	ar := fosite.NewAuthorizeRequest()
	ar.Form = url.Values{"nonce": {"111111111111"}}
	ar.SetSession(&DefaultSession{Claims: &jwt.IDTokenClaims{
		Subject: "peter",
	}, Headers: &jwt.Headers{}})

	resp.EXPECT().AddParameter("id_token", gomock.Any())
	h := &IDTokenHandleHelper{IDTokenStrategy: strat}
	err := h.IssueImplicitIDToken(context.Background(), time.Duration(0), ar, resp)
	assert.NoError(t, err)
}

func TestGetAccessTokenHash(t *testing.T) {
	ctrl := gomock.NewController(t)
	req := internal.NewMockAccessRequester(ctrl)
	resp := internal.NewMockAccessResponder(ctrl)

	defer ctrl.Finish()

	req.EXPECT().GetSession().Return(nil)
	resp.EXPECT().GetAccessToken().Return("7a35f818-9164-48cb-8c8f-e1217f44228431c41102-d410-4ed5-9276-07ba53dfdcd8")

	h := &IDTokenHandleHelper{IDTokenStrategy: strat}

	hash := h.GetAccessTokenHash(context.Background(), req, resp)
	assert.Equal(t, "Zfn_XBitThuDJiETU3OALQ", hash)
}

func TestGetAccessTokenHashWithDifferentKeyLength(t *testing.T) {
	ctrl := gomock.NewController(t)
	req := internal.NewMockAccessRequester(ctrl)
	resp := internal.NewMockAccessResponder(ctrl)

	defer ctrl.Finish()

	headers := &jwt.Headers{
		Extra: map[string]interface{}{
			"alg": "RS384",
		},
	}
	req.EXPECT().GetSession().Return(&DefaultSession{Headers: headers})
	resp.EXPECT().GetAccessToken().Return("7a35f818-9164-48cb-8c8f-e1217f44228431c41102-d410-4ed5-9276-07ba53dfdcd8")

	h := &IDTokenHandleHelper{IDTokenStrategy: strat}

	hash := h.GetAccessTokenHash(context.Background(), req, resp)
	assert.Equal(t, "VNX38yiOyeqBPheW5jDsWQKa6IjJzK66", hash)
}

func TestGetAccessTokenHashWithBadAlg(t *testing.T) {
	ctrl := gomock.NewController(t)
	req := internal.NewMockAccessRequester(ctrl)
	resp := internal.NewMockAccessResponder(ctrl)

	defer ctrl.Finish()

	headers := &jwt.Headers{
		Extra: map[string]interface{}{
			"alg": "R",
		},
	}
	req.EXPECT().GetSession().Return(&DefaultSession{Headers: headers})
	resp.EXPECT().GetAccessToken().Return("7a35f818-9164-48cb-8c8f-e1217f44228431c41102-d410-4ed5-9276-07ba53dfdcd8")

	h := &IDTokenHandleHelper{IDTokenStrategy: strat}

	hash := h.GetAccessTokenHash(context.Background(), req, resp)
	assert.Equal(t, "Zfn_XBitThuDJiETU3OALQ", hash)
}

func TestGetAccessTokenHashWithMissingKeyLength(t *testing.T) {
	ctrl := gomock.NewController(t)
	req := internal.NewMockAccessRequester(ctrl)
	resp := internal.NewMockAccessResponder(ctrl)

	defer ctrl.Finish()

	headers := &jwt.Headers{
		Extra: map[string]interface{}{
			"alg": "RS",
		},
	}
	req.EXPECT().GetSession().Return(&DefaultSession{Headers: headers})
	resp.EXPECT().GetAccessToken().Return("7a35f818-9164-48cb-8c8f-e1217f44228431c41102-d410-4ed5-9276-07ba53dfdcd8")

	h := &IDTokenHandleHelper{IDTokenStrategy: strat}

	hash := h.GetAccessTokenHash(context.Background(), req, resp)
	assert.Equal(t, "Zfn_XBitThuDJiETU3OALQ", hash)
}
