package fosite

import (
	"context"

	"github.com/pkg/errors"
)

func (f *Fosite) NewAccessResponse(ctx context.Context, requester AccessRequester) (AccessResponder, error) {
	var err error
	var tk TokenEndpointHandler

	response := NewAccessResponse()
	for _, tk = range f.TokenEndpointHandlers {
		if err = tk.PopulateTokenEndpointResponse(ctx, requester, response); errors.Cause(err) == ErrUnknownRequest {
		} else if err != nil {
			return nil, err
		}
	}

	if response.GetAccessToken() == "" || response.GetTokenType() == "" {
		return nil, errors.Wrap(ErrServerError, "Access token or token type not set")
	}

	return response, nil
}
