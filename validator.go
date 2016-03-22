package fosite

import (
	"net/http"

	"github.com/go-errors/errors"
	"golang.org/x/net/context"
)

type AuthorizedRequestValidator interface {
	ValidateRequest(ctx context.Context, req *http.Request, accessRequest AccessRequester) error
}

func (f *Fosite) ValidateRequestAuthorization(ctx context.Context, req *http.Request, session interface{}, scopes ...string) (AccessRequester, error) {
	var found bool = false
	ar := NewAccessRequest(session)
	for _, validator := range f.AuthorizedRequestValidators {
		if err := validator.ValidateRequest(ctx, req, ar); errors.Is(err, ErrUnknownRequest) {
			// Nothing to do
		} else if err != nil {
			return nil, errors.New(err)
		} else {
			found = true
		}
	}

	if !found {
		return nil, errors.New(ErrRequestUnauthorized)
	}

	if len(scopes) == 0 {
		scopes = append(scopes, f.GetMandatoryScope())
	}

	if !ar.GetGrantedScopes().Has(scopes...) {
		return nil, errors.New(ErrRequestForbidden)
	}

	return ar, nil
}
