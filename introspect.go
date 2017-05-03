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
		if err := errors.Cause(validator.IntrospectToken(ctx, token, tokenType, ar, scopes)); err == ErrUnknownRequest {
			// Nothing to do
		} else if err != nil {
			return nil, errors.Wrap(err, "A validator returned an error")
		} else {
			found = true
		}
	}

	if !found {
		return nil, errors.Wrap(ErrRequestUnauthorized, "No validator felt responsible for validating the token")
	}

	return ar, nil
}
