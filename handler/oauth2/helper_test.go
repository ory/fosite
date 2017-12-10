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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetExpiresIn(t *testing.T) {
	now := time.Now().UTC()
	r := fosite.NewAccessRequest(&fosite.DefaultSession{
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken: now.Add(time.Hour),
		},
	})
	assert.Equal(t, time.Hour, getExpiresIn(r, fosite.AccessToken, time.Millisecond, now))
}

func TestIssueAccessToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	areq := &fosite.AccessRequest{}
	aresp := &fosite.AccessResponse{Extra: map[string]interface{}{}}
	accessStrat := internal.NewMockAccessTokenStrategy(ctrl)
	accessStore := internal.NewMockAccessTokenStorage(ctrl)
	defer ctrl.Finish()

	helper := HandleHelper{
		AccessTokenStorage:  accessStore,
		AccessTokenStrategy: accessStrat,
		AccessTokenLifespan: time.Hour,
	}

	areq.Session = &fosite.DefaultSession{}
	for k, c := range []struct {
		mock func()
		err  error
	}{
		{
			mock: func() {
				accessStrat.EXPECT().GenerateAccessToken(nil, areq).Return("", "", errors.New(""))
			},
			err: errors.New(""),
		},
		{
			mock: func() {
				accessStrat.EXPECT().GenerateAccessToken(nil, areq).Return("token", "signature", nil)
				accessStore.EXPECT().CreateAccessTokenSession(nil, "signature", areq).Return(errors.New(""))
			},
			err: errors.New(""),
		},
		{
			mock: func() {
				accessStrat.EXPECT().GenerateAccessToken(nil, areq).Return("token", "signature", nil)
				accessStore.EXPECT().CreateAccessTokenSession(nil, "signature", areq).Return(nil)
			},
			err: nil,
		},
	} {
		c.mock()
		err := helper.IssueAccessToken(nil, areq, aresp)
		require.Equal(t, err == nil, c.err == nil)
		if c.err != nil {
			assert.EqualError(t, err, c.err.Error(), "Case %d", k)
		}
	}
}
