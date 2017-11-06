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
	"testing"

	"context"

	"github.com/golang/mock/gomock"
	. "github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestNewAccessResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	handler := internal.NewMockTokenEndpointHandler(ctrl)
	defer ctrl.Finish()

	f := &Fosite{}
	for k, c := range []struct {
		handlers  TokenEndpointHandlers
		mock      func()
		expectErr error
		expect    AccessResponder
	}{
		{
			mock:      func() {},
			handlers:  TokenEndpointHandlers{},
			expectErr: ErrServerError,
		},
		{
			mock: func() {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrServerError)
			},
			handlers:  TokenEndpointHandlers{handler},
			expectErr: ErrServerError,
		},
		{
			mock: func() {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers:  TokenEndpointHandlers{handler},
			expectErr: ErrServerError,
		},
		{
			mock: func() {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ AccessRequester, resp AccessResponder) {
					resp.SetAccessToken("foo")
				}).Return(nil)
			},
			handlers:  TokenEndpointHandlers{handler},
			expectErr: ErrServerError,
		},
		{
			mock: func() {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ AccessRequester, resp AccessResponder) {
					resp.SetAccessToken("foo")
					resp.SetTokenType("bar")
				}).Return(nil)
			},
			handlers: TokenEndpointHandlers{handler},
			expect: &AccessResponse{
				Extra:       map[string]interface{}{},
				AccessToken: "foo",
				TokenType:   "bar",
			},
		},
	} {
		f.TokenEndpointHandlers = c.handlers
		c.mock()
		ar, err := f.NewAccessResponse(nil, nil)
		assert.True(t, errors.Cause(err) == c.expectErr, "%d", k)
		assert.Equal(t, ar, c.expect)
		t.Logf("Passed test case %d", k)
	}
}
