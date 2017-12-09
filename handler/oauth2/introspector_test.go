// Copyright © 2017 Aeneas Rekkas <aeneas+oss@aeneas.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oauth2

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestIntrospectToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockCoreStorage(ctrl)
	chgen := internal.NewMockCoreStrategy(ctrl)
	areq := fosite.NewAccessRequest(nil)
	defer ctrl.Finish()

	v := &CoreValidator{
		CoreStrategy: chgen,
		CoreStorage:  store,
	}
	httpreq := &http.Request{Header: http.Header{}}

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should fail because no bearer token set",
			setup: func() {
				httpreq.Header.Set("Authorization", "bearer")
				chgen.EXPECT().AccessTokenSignature("").Return("")
				store.EXPECT().GetAccessTokenSession(nil, "", nil).Return(nil, errors.New(""))
				chgen.EXPECT().RefreshTokenSignature("").Return("")
				store.EXPECT().GetRefreshTokenSession(nil, "", nil).Return(nil, errors.New(""))
			},
			expectErr: fosite.ErrRequestUnauthorized,
		},
		{
			description: "should fail because retrieval fails",
			setup: func() {
				httpreq.Header.Set("Authorization", "bearer 1234")
				chgen.EXPECT().AccessTokenSignature("1234").AnyTimes().Return("asdf")
				store.EXPECT().GetAccessTokenSession(nil, "asdf", nil).Return(nil, errors.New(""))
				chgen.EXPECT().RefreshTokenSignature("1234").Return("asdf")
				store.EXPECT().GetRefreshTokenSession(nil, "asdf", nil).Return(nil, errors.New(""))
			},
			expectErr: fosite.ErrRequestUnauthorized,
		},
		{
			description: "should fail because validation fails",
			setup: func() {
				store.EXPECT().GetAccessTokenSession(nil, "asdf", nil).AnyTimes().Return(areq, nil)
				chgen.EXPECT().ValidateAccessToken(nil, areq, "1234").Return(errors.WithStack(fosite.ErrTokenExpired))
				chgen.EXPECT().RefreshTokenSignature("1234").Return("asdf")
				store.EXPECT().GetRefreshTokenSession(nil, "asdf", nil).Return(nil, errors.New(""))
			},
			expectErr: fosite.ErrTokenExpired,
		},
		{
			description: "should fail because access token invalid",
			setup: func() {
				v.DisableRefreshTokenValidation = true
				chgen.EXPECT().ValidateAccessToken(nil, areq, "1234").Return(errors.WithStack(fosite.ErrInvalidTokenFormat))
			},
			expectErr: fosite.ErrInvalidTokenFormat,
		},
		{
			description: "should pass",
			setup: func() {
				chgen.EXPECT().ValidateAccessToken(nil, areq, "1234").Return(nil)
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			err := v.IntrospectToken(nil, fosite.AccessTokenFromRequest(httpreq), fosite.AccessToken, areq, []string{})

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
