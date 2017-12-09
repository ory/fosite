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

package fosite_test

import (
	"net/http"
	"testing"

	"context"

	"fmt"

	"github.com/golang/mock/gomock"
	. "github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessTokenFromRequestNoToken(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)

	assert.Equal(t, AccessTokenFromRequest(req), "", "No token should produce an empty string")
}

func TestAccessTokenFromRequestHeader(t *testing.T) {
	token := "TokenFromHeader"

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Add("Authorization", "Bearer "+token)

	assert.Equal(t, AccessTokenFromRequest(req), token, "Token should be obtainable from header")
}

func TestAccessTokenFromRequestQuery(t *testing.T) {
	token := "TokenFromQueryParam"

	req, _ := http.NewRequest("GET", "http://example.com/test?access_token="+token, nil)

	assert.Equal(t, AccessTokenFromRequest(req), token, "Token should be obtainable from access_token query parameter")
}

func TestIntrospect(t *testing.T) {
	ctrl := gomock.NewController(t)
	validator := internal.NewMockTokenIntrospector(ctrl)
	defer ctrl.Finish()

	f := compose.ComposeAllEnabled(new(compose.Config), storage.NewMemoryStore(), []byte{}, nil).(*Fosite)

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Add("Authorization", "bearer some-token")

	for k, c := range []struct {
		description string
		scopes      []string
		setup       func()
		expectErr   error
	}{
		{
			description: "should fail",
			scopes:      []string{},
			setup: func() {
			},
			expectErr: ErrRequestUnauthorized,
		},
		{
			description: "should fail",
			scopes:      []string{"foo"},
			setup: func() {
				f.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				validator.EXPECT().IntrospectToken(nil, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrUnknownRequest)
			},
			expectErr: ErrRequestUnauthorized,
		},
		{
			description: "should fail",
			scopes:      []string{"foo"},
			setup: func() {
				validator.EXPECT().IntrospectToken(nil, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrInvalidClient)
			},
			expectErr: ErrInvalidClient,
		},
		{
			description: "should pass",
			setup: func() {
				validator.EXPECT().IntrospectToken(nil, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx context.Context, _ string, _ TokenType, accessRequest AccessRequester, _ []string) {
					accessRequest.(*AccessRequest).GrantedScopes = []string{"bar"}
				}).Return(nil)
			},
		},
		{
			description: "should pass",
			scopes:      []string{"bar"},
			setup: func() {
				validator.EXPECT().IntrospectToken(nil, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Do(func(ctx context.Context, _ string, _ TokenType, accessRequest AccessRequester, _ []string) {
					accessRequest.(*AccessRequest).GrantedScopes = []string{"bar"}
				}).Return(nil)
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			_, err := f.IntrospectToken(nil, AccessTokenFromRequest(req), AccessToken, nil, c.scopes...)
			if c.expectErr != nil {
				assert.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}
