package fosite

import (
	"net/http"

	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

type AuthorizedRequestValidator interface {
	ValidateRequest(ctx context.Context, req *http.Request, accessRequest AccessRequester) error
}

func (f *Fosite) ValidateRequestAuthorization(ctx context.Context, req *http.Request, session interface{}, scopes ...string) (AccessRequester, error) {
	var found bool = false
	ar := NewAccessRequest(session)
	for _, validator := range f.AuthorizedRequestValidators {
		if err := errors.Cause(validator.ValidateRequest(ctx, req, ar)); err == ErrUnknownRequest {
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
