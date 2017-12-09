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
	"net/http"
	"strings"

	"context"

	"github.com/pkg/errors"
)

type TokenIntrospector interface {
	IntrospectToken(ctx context.Context, token string, tokenType TokenType, accessRequest AccessRequester, scopes []string) error
}

func AccessTokenFromRequest(req *http.Request) string {
	// Acording to https://tools.ietf.org/html/rfc6750 you can pass tokens through:
	// - Form-Encoded Body Parameter. Recomended, more likely to appear. e.g.: Authorization: Bearer mytoken123
	// - URI Query Parameter e.g. access_token=mytoken123

	auth := req.Header.Get("Authorization")
	split := strings.SplitN(auth, " ", 2)
	if len(split) != 2 || !strings.EqualFold(split[0], "bearer") {
		// Nothing in Authorization header, try access_token
		// Empty string returned if there's no such parameter
		err := req.ParseForm()
		if err != nil {
			return ""
		}
		return req.Form.Get("access_token")
	}

	return split[1]
}

func (f *Fosite) IntrospectToken(ctx context.Context, token string, tokenType TokenType, session Session, scopes ...string) (AccessRequester, error) {
	var found bool = false

	ar := NewAccessRequest(session)
	for _, validator := range f.TokenIntrospectionHandlers {
		if err := errors.Cause(validator.IntrospectToken(ctx, token, tokenType, ar, scopes)); err == nil {
			found = true
		} else if err.Error() == ErrUnknownRequest.Error() {
			// Nothing to do
		} else if err != nil {
			rfcerr := ErrorToRFC6749Error(err)
			return nil, errors.WithStack(rfcerr.WithDebug("A validator returned an error"))
		}
	}

	if !found {
		return nil, errors.WithStack(ErrRequestUnauthorized.WithDebug("No validator felt responsible for validating the token"))
	}

	return ar, nil
}
