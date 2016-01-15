package fosite

import (
	"github.com/go-errors/errors"
	"golang.org/x/net/context"
	"net/http"
)

func (o *Fosite) NewAuthorizeResponse(ctx context.Context, r *http.Request, ar AuthorizeRequester) (AuthorizeResponder, error) {
	var resp = NewAuthorizeResponse()
	for _, h := range o.AuthorizeEndpointHandlers {
		if err := h.HandleAuthorizeEndpointRequest(ctx, r, ar, resp); err != nil {
			return nil, err
		}
	}

	if !ar.DidHandleAllResponseTypes() {
		return nil, errors.New(ErrUnsupportedResponseType)
	}

	return resp, nil
}
