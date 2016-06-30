package fosite

import (
	"net/http"

	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

type AuthorizedRequestValidator interface {
	ValidateRequest(ctx context.Context, req *http.Request, accessRequest AccessRequester) (context.Context, error)
}

func (f *Fosite) ValidateRequestAuthorization(ctx context.Context, req *http.Request, session interface{}, scopes ...string) (AccessRequester, error) {
	var (
		found bool = false
		err   error
	)
	ar := NewAccessRequest(session)
	for _, validator := range f.AuthorizedRequestValidators {
		ctx, err = validator.ValidateRequest(ctx, req, ar)
		if err := errors.Cause(err); err == ErrUnknownRequest {
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

	if len(scopes) == 0 {
		scopes = append(scopes, f.GetMandatoryScope())
	}

	if !ar.GetGrantedScopes().Has(scopes...) {
		return nil, errors.Wrap(ErrRequestForbidden, "one or more scopes missing")
	}

	return ar, nil
}
