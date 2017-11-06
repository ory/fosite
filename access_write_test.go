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

	"net/http"

	"github.com/golang/mock/gomock"
	. "github.com/ory/fosite"
	. "github.com/ory/fosite/internal"
	"github.com/stretchr/testify/assert"
)

func TestWriteAccessResponse(t *testing.T) {
	f := &Fosite{}
	header := http.Header{}
	ctrl := gomock.NewController(t)
	rw := NewMockResponseWriter(ctrl)
	ar := NewMockAccessRequester(ctrl)
	resp := NewMockAccessResponder(ctrl)
	defer ctrl.Finish()

	rw.EXPECT().Header().AnyTimes().Return(header)
	rw.EXPECT().WriteHeader(http.StatusOK)
	rw.EXPECT().Write(gomock.Any())
	resp.EXPECT().ToMap().Return(map[string]interface{}{})

	f.WriteAccessResponse(rw, ar, resp)
	assert.Equal(t, "application/json;charset=UTF-8", header.Get("Content-Type"))
	assert.Equal(t, "no-store", header.Get("Cache-Control"))
	assert.Equal(t, "no-cache", header.Get("Pragma"))
}
