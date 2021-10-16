package fosite

import (
	"context"
	"net/http"

	"github.com/ory/x/errorsx"
)

// NewPushedAuthorizeRequest validates the request and produces an AuthorizeRequester object that can be stored
func (f *Fosite) NewPushedAuthorizeRequest(ctx context.Context, r *http.Request) (AuthorizeRequester, error) {
	request := NewAuthorizeRequest()
	if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebug(err.Error()))
	}
	request.Form = r.Form
	request.State = request.Form.Get("state")

	// Authenticate the client in the same way as at the token endpoint
	// (Section 2.3 of [RFC6749]).
	client, err := f.AuthenticateClient(ctx, r, r.Form)
	if err != nil {
		return request, errorsx.WithStack(ErrInvalidClient.WithHint("The requested OAuth 2.0 Client could not be authenticated.").WithWrap(err).WithDebug(err.Error()))
	}
	request.Client = client

	// Reject the request if the "request_uri" authorization request
	// parameter is provided.
	if r.Form.Get("request_uri") != "" {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("The request must not contain 'request_uri'."))
	}

	// Drop the client in context so it isn't re-fetched
	ctx = context.WithValue(ctx, ClientContextKey, client)

	// Validate as if this is a new authorize request
	return f.NewAuthorizeRequest(ctx, r)
}
