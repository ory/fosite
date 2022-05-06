/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package openid

import (
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/token/jwt"
)

var strat = &DefaultStrategy{
	JWTStrategy: &jwt.RS256JWTStrategy{
		PrivateKey: internal.MustRSAKey(),
	},
	MinParameterEntropy: fosite.MinParameterEntropy,
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
				chgen.EXPECT().GenerateIDToken(nil, ar).Return("", fooErr)
			},
			expectErr: fooErr,
		},
		{
			description: "should pass",
			setup: func() {
				chgen.EXPECT().GenerateIDToken(nil, ar).AnyTimes().Return("asdf", nil)
			},
		},
	} {
		c.setup()
		token, err := h.generateIDToken(nil, ar)
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
	err := h.IssueExplicitIDToken(nil, ar, resp)
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
	err := h.IssueImplicitIDToken(nil, ar, resp)
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

	hash := h.GetAccessTokenHash(nil, req, resp)
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

	hash := h.GetAccessTokenHash(nil, req, resp)
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

	hash := h.GetAccessTokenHash(nil, req, resp)
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

	hash := h.GetAccessTokenHash(nil, req, resp)
	assert.Equal(t, "Zfn_XBitThuDJiETU3OALQ", hash)
}
