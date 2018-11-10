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

package fosite_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/ory/fosite"
	"github.com/ory/fosite/internal"
)

func TestWriteIntrospectionError(t *testing.T) {
	f := new(Fosite)
	c := gomock.NewController(t)
	defer c.Finish()

	rw := internal.NewMockResponseWriter(c)

	rw.EXPECT().WriteHeader(http.StatusUnauthorized) //[]byte("{\"active\":\"false\"}"))
	rw.EXPECT().Header().AnyTimes().Return(http.Header{})
	rw.EXPECT().Write(gomock.Any())
	f.WriteIntrospectionError(rw, errors.WithStack(ErrRequestUnauthorized))

	rw.EXPECT().Write([]byte("{\"active\":false}\n"))
	f.WriteIntrospectionError(rw, errors.New(""))

	f.WriteIntrospectionError(rw, nil)
}

func TestWriteIntrospectionResponse(t *testing.T) {
	f := new(Fosite)
	c := gomock.NewController(t)
	defer c.Finish()

	rw := internal.NewMockResponseWriter(c)
	rw.EXPECT().Write(gomock.Any()).AnyTimes()
	f.WriteIntrospectionResponse(rw, &IntrospectionResponse{
		AccessRequester: NewAccessRequest(nil),
	})
}

func TestWriteIntrospectionResponseBody(t *testing.T) {
	f := new(Fosite)
	ires := &IntrospectionResponse{}
	rw := httptest.NewRecorder()

	for _, c := range []struct {
		description string
		setup       func()
		active      bool
		hasExp      bool
	}{
		{
			description: "should success for not expired access token",
			setup: func() {
				ires.Active = true
				ires.TokenType = AccessToken
				sess := &DefaultSession{}
				sess.SetExpiresAt(ires.TokenType, time.Now().Add(time.Hour*2))
				ires.AccessRequester = NewAccessRequest(sess)
			},
			active: true,
			hasExp: true,
		},
		{
			description: "should success for expired access token",
			setup: func() {
				ires.Active = false
				ires.TokenType = AccessToken
				sess := &DefaultSession{}
				sess.SetExpiresAt(ires.TokenType, time.Now().Add(-time.Hour*2))
				ires.AccessRequester = NewAccessRequest(sess)
			},
			active: false,
			hasExp: false,
		},
		{
			description: "should success for ExpiresAt not set access token",
			setup: func() {
				ires.Active = true
				ires.TokenType = AccessToken
				sess := &DefaultSession{}
				sess.SetExpiresAt(ires.TokenType, time.Time{})
				ires.AccessRequester = NewAccessRequest(sess)
			},
			active: true,
			hasExp: false,
		},
	} {
		t.Run(c.description, func(t *testing.T) {
			c.setup()
			f.WriteIntrospectionResponse(rw, ires)
			var params struct {
				Active bool   `json:"active"`
				Exp    *int64 `json:"exp"`
				Iat    *int64 `json:"iat"`
			}
			err := json.NewDecoder(rw.Body).Decode(&params)
			require.NoError(t, err)
			assert.Equal(t, c.active, params.Active)
			if c.active {
				assert.NotNil(t, params.Iat)
				if c.hasExp {
					assert.NotNil(t, params.Exp)
				} else {
					assert.Nil(t, params.Exp)
				}
			}
		})
	}
}
