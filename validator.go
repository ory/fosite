package fosite

import (
	"net/http"

	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

type TokenValidator interface {
	ValidateToken(ctx context.Context, token string, tokenType TokenType, accessRequest AccessRequester) error
}

func (f *Fosite) ValidateToken(ctx context.Context, token string, tokenType TokenType, session interface{}, scopes ...string) (AccessRequester, error) {
	var found bool = false
	ar := NewAccessRequest(session)
	for _, validator := range f.Validators {
		if err := errors.Cause(validator.ValidateToken(ctx, token, tokenType, ar)); err == ErrUnknownRequest {
			// Nothing to do
		} else if err != nil {
			return nil, errors.Wrap(err, "")
		} else {
			found = true
		}
	}

	if !found {
		return nil, errors.Wrap(ErrRequestUnauthorized, "")
	}
	if !ar.GetGrantedScopes().Has(scopes...) {
		return nil, errors.Wrap(ErrRequestForbidden, "one or more scopes missing")
	}

	return ar, nil
}
