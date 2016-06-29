package fosite

import (
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

func (o *Fosite) NewAuthorizeResponse(ctx context.Context, r *http.Request, ar AuthorizeRequester, session interface{}) (context.Context, AuthorizeResponder, error) {
	var resp = &AuthorizeResponse{
		Header:   http.Header{},
		Query:    url.Values{},
		Fragment: url.Values{},
	}

	ar.SetSession(session)
	for _, h := range o.AuthorizeEndpointHandlers {
		ctx, err := h.HandleAuthorizeEndpointRequest(ctx, r, ar, resp)
		if err != nil {
			return ctx, nil, err
		}
	}

	if !ar.DidHandleAllResponseTypes() {
		return ctx, nil, errors.Wrap(ErrUnsupportedResponseType, "")
	}

	return ctx, resp, nil
}
