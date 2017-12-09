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

package fosite

import (
	"encoding/json"
	"fmt"
	"net/http"

	"context"

	"github.com/pkg/errors"
)

// NewRevocationRequest handles incoming token revocation requests and
// validates various parameters as specified in:
// https://tools.ietf.org/html/rfc7009#section-2.1
//
// The authorization server first validates the client credentials (in
// case of a confidential client) and then verifies whether the token
// was issued to the client making the revocation request.  If this
// validation fails, the request is refused and the client is informed
// of the error by the authorization server as described below.
//
// In the next step, the authorization server invalidates the token.
// The invalidation takes place immediately, and the token cannot be
// used again after the revocation.
//
// * https://tools.ietf.org/html/rfc7009#section-2.2
// An invalid token type hint value is ignored by the authorization
// server and does not influence the revocation response.
func (f *Fosite) NewRevocationRequest(ctx context.Context, r *http.Request) error {
	if r.Method != "POST" {
		return errors.WithStack(ErrInvalidRequest.WithDebug("HTTP method is not POST"))
	} else if err := r.ParseForm(); err != nil {
		return errors.WithStack(ErrInvalidRequest.WithDebug(err.Error()))
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		return errors.WithStack(ErrInvalidRequest.WithDebug("HTTP Authorization header missing or invalid"))
	}

	client, err := f.Store.GetClient(ctx, clientID)
	if err != nil {
		return errors.WithStack(ErrInvalidClient.WithDebug(err.Error()))
	}

	// Enforce client authentication for confidential clients
	if !client.IsPublic() {
		if err := f.Hasher.Compare(client.GetHashedSecret(), []byte(clientSecret)); err != nil {
			return errors.WithStack(ErrInvalidClient.WithDebug(err.Error()))
		}
	}

	token := r.PostForm.Get("token")
	tokenTypeHint := TokenType(r.PostForm.Get("token_type_hint"))

	var found bool
	for _, loader := range f.RevocationHandlers {
		if err := loader.RevokeToken(ctx, token, tokenTypeHint, client); err == nil {
			found = true
		} else if errors.Cause(err).Error() == ErrUnknownRequest.Error() {
			// do nothing
		} else if err != nil {
			return err
		}
	}

	if !found {
		return errors.WithStack(ErrInvalidRequest)
	}

	return nil
}

// WriteRevocationResponse writes a token revocation response as specified in:
// https://tools.ietf.org/html/rfc7009#section-2.2
//
// The authorization server responds with HTTP status code 200 if the
// token has been revoked successfully or if the client submitted an
// invalid token.
//
// Note: invalid tokens do not cause an error response since the client
// cannot handle such an error in a reasonable way.  Moreover, the
// purpose of the revocation request, invalidating the particular token,
// is already achieved.
func (f *Fosite) WriteRevocationResponse(rw http.ResponseWriter, err error) {
	if err == nil {
		rw.WriteHeader(http.StatusOK)
		return
	}

	switch errors.Cause(err).Error() {
	case ErrInvalidRequest.Error():
		fallthrough
	case ErrInvalidClient.Error():
		rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

		js, err := json.Marshal(ErrInvalidClient)
		if err != nil {
			http.Error(rw, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		rw.WriteHeader(ErrInvalidClient.Code)
		rw.Write(js)
	default:
		// 200 OK
		rw.WriteHeader(http.StatusOK)
	}
}
