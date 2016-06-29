package fosite

import (
	"net/http"

	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

func (f *Fosite) NewAccessResponse(ctx context.Context, req *http.Request, requester AccessRequester) (context.Context, AccessResponder, error) {
	var err error
	var tk TokenEndpointHandler

	response := NewAccessResponse()
	for _, tk = range f.TokenEndpointHandlers {
		if ctx, err = tk.PopulateTokenEndpointResponse(ctx, req, requester, response); errors.Cause(err) == ErrUnknownRequest {
		} else if err != nil {
			return ctx, nil, err
		}
	}

	if response.GetAccessToken() == "" || response.GetTokenType() == "" {
		return ctx, nil, errors.Wrap(ErrServerError, "Access token or token type not set")
	}

	return ctx, response, nil
}
