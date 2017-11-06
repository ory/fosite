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

	"github.com/golang/mock/gomock"
	. "github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/pkg/errors"
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
