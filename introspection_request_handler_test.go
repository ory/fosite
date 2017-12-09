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
	"net/url"
	"testing"

	"fmt"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	. "github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/storage"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntrospectionResponse(t *testing.T) {
	r := &fosite.IntrospectionResponse{
		AccessRequester: fosite.NewAccessRequest(nil),
		Active:          true,
	}

	assert.Equal(t, r.AccessRequester, r.GetAccessRequester())
	assert.Equal(t, r.Active, r.IsActive())
}

func TestNewIntrospectionRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	validator := internal.NewMockTokenIntrospector(ctrl)
	defer ctrl.Finish()

	f := compose.ComposeAllEnabled(new(compose.Config), storage.NewMemoryStore(), []byte{}, nil).(*Fosite)
	httpreq := &http.Request{
		Method: "POST",
		Header: http.Header{},
		Form:   url.Values{},
	}
	newErr := errors.New("asdf")

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
		isActive    bool
	}{
		{
			description: "should fail",
			setup: func() {
			},
			expectErr: ErrInvalidRequest,
		},
		{
			description: "should fail",
			setup: func() {
				f.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				httpreq = &http.Request{
					Method: "POST",
					Header: http.Header{
						"Authorization": []string{"bearer some-token"},
					},
					PostForm: url.Values{
						"token": []string{"introspect-token"},
					},
				}
				validator.EXPECT().IntrospectToken(nil, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				validator.EXPECT().IntrospectToken(nil, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(newErr)
			},
			isActive:  false,
			expectErr: ErrInactiveToken,
		},
		{
			description: "should pass",
			setup: func() {
				f.TokenIntrospectionHandlers = TokenIntrospectionHandlers{validator}
				httpreq = &http.Request{
					Method: "POST",
					Header: http.Header{
						"Authorization": []string{"bearer some-token"},
					},
					PostForm: url.Values{
						"token": []string{"introspect-token"},
					},
				}
				validator.EXPECT().IntrospectToken(nil, "some-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				validator.EXPECT().IntrospectToken(nil, "introspect-token", gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			isActive: true,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			res, err := f.NewIntrospectionRequest(nil, httpreq, &DefaultSession{})

			if c.expectErr != nil {
				assert.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, c.isActive, res.IsActive())
			}
		})
	}
}
